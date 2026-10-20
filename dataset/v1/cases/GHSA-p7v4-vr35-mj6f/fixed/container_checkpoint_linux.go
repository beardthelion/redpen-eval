// Source: https://github.com/containerd/containerd
// Ref: 928c03c6898cad95f795300281fdff0dbc55a32f Path: internal/cri/server/container_checkpoint_linux.go
// Excerpted and modified from https://github.com/containerd/containerd@928c03c6898cad95f795300281fdff0dbc55a32f on 2026-10-20
// License: Apache-2.0, see licenses/containerd__containerd/LICENSE
// Copyright The containerd Authors.
func (c *criService) CRImportCheckpoint(
	ctx context.Context,
	meta *containerstore.Metadata,
	sandbox *sandbox.Sandbox,
	sandboxConfig *runtime.PodSandboxConfig,
) (ctrID string, retErr error) {
	if !c.config.EnableExperimentalRestoreViaCreate {
		return "", errors.New("checkpoint restore via CreateContainer is disabled by configuration")
	}
	if err := c.checkCriu(); err != nil {
		return "", fmt.Errorf("checkpoint restore is not enabled: %w", err)
	}

	var mountPoint string
	start := time.Now()
	// Ensure that the image to restore the checkpoint from has been provided.
	if meta.Config.Image == nil || meta.Config.Image.Image == "" {
		return "", errors.New(`attribute "image" missing from container definition`)
	}

	inputImage := meta.Config.Image.Image
	createAnnotations := meta.Config.Annotations
	createLabels := meta.Config.Labels

	restoreStorageImageID, err := c.checkIfCheckpointOCIImage(ctx, inputImage)
	if err != nil {
		return "", err
	}

	mountPoint, err = os.MkdirTemp("", "checkpoint")
	if err != nil {
		return "", err
	}
	defer func() {
		if err := os.RemoveAll(mountPoint); err != nil {
			log.G(ctx).Errorf("Could not recursively remove %s: %q", mountPoint, err)
		}
	}()
	var archiveFile *os.File
	if restoreStorageImageID != "" {
		log.G(ctx).Debugf("Restoring from oci image %s", inputImage)
		platform, err := c.sandboxService.SandboxPlatform(ctx, sandbox.Sandboxer, sandbox.ID)
		if err != nil {
			return "", fmt.Errorf("failed to query sandbox platform: %w", err)
		}
		img, err := c.client.ImageService().Get(ctx, restoreStorageImageID)
		if err != nil {
			return "", err
		}

		i := client.NewImageWithPlatform(c.client, img, platforms.Only(platform))
		diffIDs, err := i.RootFS(ctx)
		if err != nil {
			return "", err
		}
		chainID := identity.ChainID(diffIDs).String()
		ociRuntime, err := c.config.GetSandboxRuntime(sandboxConfig, sandbox.Metadata.RuntimeHandler)
		if err != nil {
			return "", fmt.Errorf("failed to get sandbox runtime: %w", err)
		}
		s := c.client.SnapshotService(c.RuntimeSnapshotter(ctx, ociRuntime))

		mounts, err := s.View(ctx, mountPoint, chainID)
		if err != nil {
			if errdefs.IsAlreadyExists(err) {
				mounts, err = s.Mounts(ctx, mountPoint)
			}
			if err != nil {
				return "", err
			}
		}
		if err := mount.All(mounts, mountPoint); err != nil {
			return "", err
		}
	} else {

		archiveFile, err = os.Open(inputImage)
		if err != nil {
			return "", fmt.Errorf("failed to open checkpoint archive %s for import: %w", inputImage, err)
		}
		defer func(f *os.File) {
			if err := f.Close(); err != nil {
				log.G(ctx).Errorf("Unable to close file %s: %q", f.Name(), err)
			}
		}(archiveFile)

		filter := archive.WithFilter(func(hdr *tar.Header) (bool, error) {
			// Reject entry types the checkpoint code never produces (symlinks,
			// hardlinks, device/fifo nodes) so they are not recreated on disk.
			if !checkpointArchiveEntryAllowed(hdr) {
				log.G(ctx).Warnf("Skipping unexpected checkpoint archive entry %q (type %d)", hdr.Name, hdr.Typeflag)
				return false, nil
			}
			// The checkpoint archive is unpacked twice if using a tar file directly.
			// The first time only the metadata files are relevant to prepare the
			// restore operation. This filter function ignores the large parts of
			// the checkpoint archive. This is usually the actual checkpoint
			// coming from CRIU as well as the rootfs diff tar file.
			excludePatterns := []string{
				"artifacts",
				"ctr.log",
				crmetadata.RootFsDiffTar,
				crmetadata.NetworkStatusFile,
				crmetadata.DeletedFilesFile,
				crmetadata.CheckpointDirectory,
			}
			for _, pattern := range excludePatterns {
				if strings.HasPrefix(hdr.Name, pattern) {
					return false, nil
				}
			}
			return true, nil
		})

		_, err = archive.Apply(
			ctx,
			mountPoint,
			archiveFile,
			[]archive.ApplyOpt{filter}...,
		)

		if err != nil {
			return "", fmt.Errorf("unpacking of checkpoint archive %s failed: %w", mountPoint, err)
		}
		log.G(ctx).Debugf("Unpacked checkpoint in %s", mountPoint)
	}
	// Load spec.dump from temporary directory
	dumpSpec := new(spec.Spec)
	if _, err := crmetadata.ReadJSONFile(dumpSpec, mountPoint, crmetadata.SpecDumpFile); err != nil {
		return "", fmt.Errorf("failed to read %q: %w", crmetadata.SpecDumpFile, err)
	}

	// Load config.dump from temporary directory
	config := new(crmetadata.ContainerConfig)
	if _, err := crmetadata.ReadJSONFile(config, mountPoint, crmetadata.ConfigDumpFile); err != nil {
		return "", fmt.Errorf("failed to read %q: %w", crmetadata.ConfigDumpFile, err)
	}

	// Load status.dump from temporary directory
	containerStatus := new(runtime.ContainerStatus)
	if _, err := crmetadata.ReadJSONFile(containerStatus, mountPoint, crmetadata.StatusDumpFile); err != nil {
		return "", fmt.Errorf("failed to read %q: %w", crmetadata.StatusDumpFile, err)
	}

	if meta.SandboxID == "" {
		// restore into previous sandbox
		meta.SandboxID = dumpSpec.Annotations[annotations.SandboxID]
		ctrID = config.ID
	} else {
		ctrID = ""
	}

	ctrMetadata := runtime.ContainerMetadata{}

	if meta.Config.Metadata != nil && meta.Config.Metadata.Name != "" {
		ctrMetadata.Name = containerStatus.GetMetadata().GetName()
	}

	originalAnnotations := containerStatus.GetAnnotations()
	if originalAnnotations == nil {
		originalAnnotations = make(map[string]string)
	}
	originalLabels := containerStatus.GetLabels()

	sandboxUID := sandboxConfig.GetMetadata().GetUid()

	if sandboxUID != "" {
		if _, ok := originalLabels[crilabels.KubernetesPodUIDLabel]; ok {
			originalLabels[crilabels.KubernetesPodUIDLabel] = sandboxUID
		}
		if _, ok := originalAnnotations[crilabels.KubernetesPodUIDLabel]; ok {
			originalAnnotations[crilabels.KubernetesPodUIDLabel] = sandboxUID
		}
	}

	if createLabels != nil {
		fixupLabels := []string{
			// Update the container name. It has already been update in metadata.Name.
			// It also needs to be updated in the container labels.
			crilabels.KubernetesContainerNameLabel,
			// Update pod name in the labels.
			crilabels.KubernetesPodNameLabel,
			// Also update namespace.
			crilabels.KubernetesPodNamespaceLabel,
		}

		for _, annotation := range fixupLabels {
			_, ok1 := createLabels[annotation]
			_, ok2 := originalLabels[annotation]

			// If the value is not set in the original container or
			// if it is not set in the new container, just skip
			// the step of updating metadata.
			if ok1 && ok2 {
				originalLabels[annotation] = createLabels[annotation]
			}
		}
	}

	originalAnnotations = filterAndMergeAnnotations(
		ctx,
		originalAnnotations,
		createAnnotations,
	)

	var containerdImage client.Image

	containerdImage, err = c.client.GetImage(ctx, config.RootfsImageRef)
	if err != nil {
		if !errdefs.IsNotFound(err) {
			return "", fmt.Errorf("failed to get checkpoint base image %s: %w", config.RootfsImageRef, err)
		}
		// Pulling the image the checkpoint is based on. This is a bit different
		// than automatic image pulling. The checkpoint image is not automatically
		// pulled, but the image the checkpoint is based on.
		// During checkpointing the base image of the checkpoint is stored in the
		// checkpoint archive as NAME@DIGEST. The checkpoint archive also contains
		// the tag with which it was initially pulled.
		// First step is to pull NAME@DIGEST
		containerdImage, err = c.client.Pull(ctx, config.RootfsImageRef)
		if err != nil {
			return "", fmt.Errorf("failed to pull checkpoint base image %s: %w", config.RootfsImageRef, err)
		}
	}

	if _, err := reference.ParseAnyReference(config.RootfsImageName); err != nil {
		return "", fmt.Errorf("error parsing reference: %q is not a valid repository/tag %v", config.RootfsImageName, err)
	}

	var image imagestore.Image
	for i := 1; i < 500; i++ {
		// This is probably wrong. Not sure how to wait for an image to appear in
		// the image (or content) store.
		log.G(ctx).Debugf("Trying to resolve %s:%d", containerdImage.Name(), i)
		image, err = c.LocalResolve(containerdImage.Name())
		if err == nil {
			break
		}
		time.Sleep(time.Microsecond * time.Duration(i))
	}
	if err != nil {
		return "", fmt.Errorf("failed to resolve image %q during checkpoint import: %w", config.RootfsImageName, err)
	}
	imageConfig := image.ImageSpec.Config
	env := append([]string{}, imageConfig.Env...)
	for _, e := range meta.Config.GetEnvs() {
		env = append(env, e.GetKey()+"="+string(e.GetValue()))
	}
	imageConfig.Env = append(imageConfig.Env, env...)

	originalAnnotations["restored"] = "true"
	originalAnnotations["checkpointedAt"] = config.CheckpointedAt.Format(time.RFC3339Nano)
	originalAnnotations["checkpointImage"] = meta.Config.Image.GetUserSpecifiedImage()

	meta.Config.Annotations = originalAnnotations

	// Remove the checkpoint image name and show the base image name in the metadata.
	// The checkpoint image name is still available in the annotations.
	meta.Config.Image.Image = containerStatus.Image.GetImage()
	meta.Config.Image.UserSpecifiedImage = containerStatus.Image.GetUserSpecifiedImage()

	cstatus, err := c.sandboxService.SandboxStatus(ctx, sandbox.Sandboxer, sandbox.ID, false)
	if err != nil {
		return "", fmt.Errorf("failed to get controller status: %w", err)
	}

	containerRootDir, err := c.createContainer(
		&createContainerRequest{
			ctx:                   ctx,
			containerID:           meta.ID,
			sandbox:               sandbox,
			sandboxID:             meta.SandboxID,
			imageID:               image.ID,
			containerConfig:       meta.Config,
			imageConfig:           &imageConfig,
			podSandboxConfig:      sandboxConfig,
			sandboxRuntimeHandler: sandbox.Metadata.RuntimeHandler,
			sandboxPid:            cstatus.Pid,
			NetNSPath:             sandbox.NetNSPath,
			containerName:         containerName,
			containerdImage:       &containerdImage,
			meta:                  meta,
			restore:               true,
			start:                 start,
		},
	)
	if err != nil {
		return "", err
	}

	// Confine all checkpoint content to a dedicated subdirectory of the container
	// state dir instead of unpacking it directly into the state dir, so it cannot
	// collide with containerd's own files there. Create it fresh; RemoveAll unlinks
	// any pre-existing entry without following it.
	restoreDir := filepath.Join(containerRootDir, checkpointRestoreDir)
	if err := os.RemoveAll(restoreDir); err != nil {
		return "", err
	}
	if err := os.Mkdir(restoreDir, 0o700); err != nil {
		return "", err
	}

	if restoreStorageImageID != "" {
		if err := fs.CopyDir(restoreDir, mountPoint); err != nil {
			return "", err
		}
		if err := mount.UnmountAll(mountPoint, 0); err != nil {
			return "", err
		}
		// fs.CopyDir recreates any symlinks/special files from the image; reject
		// them here so restore-time consumers only ever open regular files.
		if err := assertCheckpointDirSafe(restoreDir); err != nil {
			return "", err
		}
	} else {
		// unpack the checkpoint archive
		filter := archive.WithFilter(func(hdr *tar.Header) (bool, error) {
			// Reject entry types the checkpoint code never produces (symlinks,
			// hardlinks, device/fifo nodes) so they are not recreated on disk.
			if !checkpointArchiveEntryAllowed(hdr) {
				log.G(ctx).Warnf("Skipping unexpected checkpoint archive entry %q (type %d)", hdr.Name, hdr.Typeflag)
				return false, nil
			}
			excludePatterns := []string{
				crmetadata.ConfigDumpFile,
				crmetadata.SpecDumpFile,
				crmetadata.StatusDumpFile,
			}

			for _, pattern := range excludePatterns {
				if strings.HasPrefix(hdr.Name, pattern) {
					return false, nil
				}
			}

			return true, nil
		})

		// Start from the beginning of the checkpoint archive
		archiveFile.Seek(0, 0)
		_, err = archive.Apply(ctx, restoreDir, archiveFile, []archive.ApplyOpt{filter}...)

		if err != nil {
			return "", fmt.Errorf("unpacking of checkpoint archive %s failed: %w", restoreDir, err)
		}
	}
	log.G(ctx).Debugf("Unpacked checkpoint in %s", restoreDir)

	// Restore container log file (if it exists).
	//
	// container.log was unpacked from a checkpoint archive/OCI image, so it is
	// copied without following a final-component symlink.
	containerLog := filepath.Join(restoreDir, "container.log")
	if err := copyNoFollow(containerLog, meta.LogPath, 0600); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("restoring container log file %s failed: %w", containerLog, err)
		}
	}
	return meta.ID, nil
}
