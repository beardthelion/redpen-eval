// Source: https://github.com/podman-container-tools/podman
// Ref: 7728ba0a90094408ad9078e36c3622a651d49616 Path: pkg/specgen/generate/container_create.go
// Excerpted and modified from https://github.com/podman-container-tools/podman@7728ba0a90094408ad9078e36c3622a651d49616 on 2026-10-20
// License: Apache-2.0, see licenses/podman-container-tools__podman/LICENSE
// Copyright the podman-container-tools/podman contributors
func MakeContainer(ctx context.Context, rt *libpod.Runtime, s *specgen.SpecGenerator, clone bool, c *libpod.Container) (*specs.Spec, *specgen.SpecGenerator, []libpod.CtrCreateOption, error) {
	rtc, err := rt.GetConfigNoCopy()
	if err != nil {
		return nil, nil, nil, err
	}

	rlimits, err := specgenutil.GenRlimits(rtc.Ulimits())
	if err != nil {
		return nil, nil, nil, err
	}
	s.Rlimits = append(rlimits, s.Rlimits...)

	if s.OOMScoreAdj == nil {
		s.OOMScoreAdj = rtc.Containers.OOMScoreAdj
	}

	if len(rtc.Containers.CgroupConf.Get()) > 0 {
		if s.ResourceLimits == nil {
			s.ResourceLimits = &specs.LinuxResources{}
		}
		if s.ResourceLimits.Unified == nil {
			s.ResourceLimits.Unified = make(map[string]string)
		}
		for _, cgroupConf := range rtc.Containers.CgroupConf.Get() {
			key, val, hasVal := strings.Cut(cgroupConf, "=")
			if !hasVal {
				return nil, nil, nil, fmt.Errorf("CgroupConf %s from containers.conf invalid, must be name=value", cgroupConf)
			}
			if _, ok := s.ResourceLimits.Unified[key]; !ok {
				s.ResourceLimits.Unified[key] = val
			}
		}
	}

	// If joining a pod, retrieve the pod for use, and its infra container
	var pod *libpod.Pod
	var infra *libpod.Container
	if s.Pod != "" {
		pod, err = rt.LookupPod(s.Pod)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("retrieving pod %s: %w", s.Pod, err)
		}
		if pod.HasInfraContainer() {
			infra, err = pod.InfraContainer()
			if err != nil {
				return nil, nil, nil, err
			}
		}
	}

	options := []libpod.CtrCreateOption{}
	compatibleOptions := &libpod.InfraInherit{}
	var infraSpec *specs.Spec
	if infra != nil {
		options, infraSpec, compatibleOptions, err = Inherit(infra, s, rt)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	if err := specgen.FinishThrottleDevices(s); err != nil {
		return nil, nil, nil, err
	}

	// Set defaults for unset namespaces
	if s.PidNS.IsDefault() {
		defaultNS, err := GetDefaultNamespaceMode("pid", rtc, pod)
		if err != nil {
			return nil, nil, nil, err
		}
		s.PidNS = defaultNS
	}
	if s.IpcNS.IsDefault() {
		defaultNS, err := GetDefaultNamespaceMode("ipc", rtc, pod)
		if err != nil {
			return nil, nil, nil, err
		}
		s.IpcNS = defaultNS
	}
	if s.UtsNS.IsDefault() {
		defaultNS, err := GetDefaultNamespaceMode("uts", rtc, pod)
		if err != nil {
			return nil, nil, nil, err
		}
		s.UtsNS = defaultNS
	}
	if s.UserNS.IsDefault() {
		defaultNS, err := GetDefaultNamespaceMode("user", rtc, pod)
		if err != nil {
			return nil, nil, nil, err
		}
		s.UserNS = defaultNS
		value := string(s.UserNS.NSMode)
		if s.UserNS.Value != "" {
			value = value + ":" + s.UserNS.Value
		}
		mappings, err := util.ParseIDMapping(namespaces.UsernsMode(value), nil, nil, "", "")
		if err != nil {
			return nil, nil, nil, err
		}
		s.IDMappings = mappings
	}
	if s.NetNS.IsDefault() {
		defaultNS, err := GetDefaultNamespaceMode("net", rtc, pod)
		if err != nil {
			return nil, nil, nil, err
		}
		s.NetNS = defaultNS
	}
	if s.CgroupNS.IsDefault() {
		defaultNS, err := GetDefaultNamespaceMode("cgroup", rtc, pod)
		if err != nil {
			return nil, nil, nil, err
		}
		s.CgroupNS = defaultNS
	}

	if s.ContainerCreateCommand != nil {
		options = append(options, libpod.WithCreateCommand(s.ContainerCreateCommand))
	}

	if s.Rootfs != "" {
		rootfsOverlay := false
		if s.RootfsOverlay != nil {
			rootfsOverlay = *s.RootfsOverlay
		}
		options = append(options, libpod.WithRootFS(s.Rootfs, rootfsOverlay, s.RootfsMapping))
	}

	newImage, resolvedImageName, imageData, err := getImageFromSpec(ctx, rt, s)
	if err != nil {
		return nil, nil, nil, err
	}

	if imageData != nil {
		ociRuntimeVariant := rtc.Engine.ImagePlatformToRuntime(imageData.Os, imageData.Architecture)
		// Don't unnecessarily set and invoke additional libpod
		// option if OCI runtime is still default.
		if ociRuntimeVariant != rtc.Engine.OCIRuntime {
			options = append(options, libpod.WithCtrOCIRuntime(ociRuntimeVariant))
		}
	}

	if newImage != nil {
		// If the input name changed, we could properly resolve the
		// image. Otherwise, it must have been an ID where we're
		// defaulting to the first name or an empty one if no names are
		// present.
		if strings.HasPrefix(newImage.ID(), resolvedImageName) {
			names := newImage.Names()
			if len(names) > 0 {
				resolvedImageName = names[0]
			}
		}

		options = append(options, libpod.WithRootFSFromImage(newImage.ID(), resolvedImageName, s.RawImageName))
	}

	_, err = rt.LookupPod(s.Hostname)
	if len(s.Hostname) > 0 && !s.UtsNS.IsPrivate() && err == nil {
		// ok, we are incorrectly setting the pod as the hostname, let's undo that before validation
		s.Hostname = ""
	}

	// Set defaults if network info is not provided
	if s.NetNS.IsPrivate() || s.NetNS.IsDefault() {
		if rootless.IsRootless() {
			// when we are rootless we default to default_rootless_network_cmd from containers.conf
			conf, err := rt.GetConfigNoCopy()
			if err != nil {
				return nil, nil, nil, err
			}
			switch conf.Network.DefaultRootlessNetworkCmd {
			case slirp4netns.BinaryName, "":
				s.NetNS.NSMode = specgen.Slirp
			case pasta.BinaryName:
				s.NetNS.NSMode = specgen.Pasta
			default:
				return nil, nil, nil, fmt.Errorf("invalid default_rootless_network_cmd option %q",
					conf.Network.DefaultRootlessNetworkCmd)
			}
		} else {
			// as root default to bridge
			s.NetNS.NSMode = specgen.Bridge
		}
	}

	if err := s.Validate(); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid config provided: %w", err)
	}

	finalMounts, finalVolumes, finalOverlays, err := finalizeMounts(ctx, s, rt, rtc, newImage)
	if err != nil {
		return nil, nil, nil, err
	}

	if len(s.HostUsers) > 0 {
		options = append(options, libpod.WithHostUsers(s.HostUsers))
	}

	command := makeCommand(s, imageData)

	infraVol := len(compatibleOptions.Mounts) > 0 || len(compatibleOptions.Volumes) > 0 || len(compatibleOptions.ImageVolumes) > 0 || len(compatibleOptions.OverlayVolumes) > 0
	opts, err := createContainerOptions(rt, s, pod, finalVolumes, finalOverlays, imageData, command, infraVol, *compatibleOptions)
	if err != nil {
		return nil, nil, nil, err
	}
	options = append(options, opts...)

	if containerType := s.InitContainerType; len(containerType) > 0 {
		options = append(options, libpod.WithInitCtrType(containerType))
	}
	if len(s.Name) > 0 {
		logrus.Debugf("setting container name %s", s.Name)
		options = append(options, libpod.WithName(s.Name))
	}
	if len(s.Devices) > 0 {
		opts = ExtractCDIDevices(s)
		options = append(options, opts...)
	}
	runtimeSpec, err := SpecGenToOCI(ctx, s, rt, rtc, newImage, finalMounts, pod, command, compatibleOptions)
	if err != nil {
		return nil, nil, nil, err
	}
	if clone { // the container fails to start if cloned due to missing Linux spec entries
		if c == nil {
			return nil, nil, nil, errors.New("the given container could not be retrieved")
		}
		conf := c.Config()
		if conf != nil && conf.Spec != nil && conf.Spec.Linux != nil {
			out, err := json.Marshal(conf.Spec.Linux)
			if err != nil {
				return nil, nil, nil, err
			}
			resources := runtimeSpec.Linux.Resources

			// resources get overwritten similarly to pod inheritance, manually assign here if there is a new value
			marshalRes, err := json.Marshal(resources)
			if err != nil {
				return nil, nil, nil, err
			}

			err = json.Unmarshal(out, runtimeSpec.Linux)
			if err != nil {
				return nil, nil, nil, err
			}

			err = json.Unmarshal(marshalRes, runtimeSpec.Linux.Resources)
			if err != nil {
				return nil, nil, nil, err
			}
		}
		if s.ResourceLimits != nil {
			switch {
			case s.ResourceLimits.CPU != nil:
				runtimeSpec.Linux.Resources.CPU = s.ResourceLimits.CPU
			case s.ResourceLimits.Memory != nil:
				runtimeSpec.Linux.Resources.Memory = s.ResourceLimits.Memory
			case s.ResourceLimits.BlockIO != nil:
				runtimeSpec.Linux.Resources.BlockIO = s.ResourceLimits.BlockIO
			case s.ResourceLimits.Devices != nil:
				runtimeSpec.Linux.Resources.Devices = s.ResourceLimits.Devices
			}
		}
	}
	if len(s.HostDeviceList) > 0 {
		options = append(options, libpod.WithHostDevice(s.HostDeviceList))
	}
	if infraSpec != nil && infraSpec.Linux != nil { // if we are inheriting Linux info from a pod...
		// Pass Security annotations
		if len(infraSpec.Annotations[define.InspectAnnotationLabel]) > 0 && len(runtimeSpec.Annotations[define.InspectAnnotationLabel]) == 0 {
			runtimeSpec.Annotations[define.InspectAnnotationLabel] = infraSpec.Annotations[define.InspectAnnotationLabel]
		}
		if len(infraSpec.Annotations[define.InspectAnnotationSeccomp]) > 0 && len(runtimeSpec.Annotations[define.InspectAnnotationSeccomp]) == 0 {
			runtimeSpec.Annotations[define.InspectAnnotationSeccomp] = infraSpec.Annotations[define.InspectAnnotationSeccomp]
		}
		if len(infraSpec.Annotations[define.InspectAnnotationApparmor]) > 0 && len(runtimeSpec.Annotations[define.InspectAnnotationApparmor]) == 0 {
			runtimeSpec.Annotations[define.InspectAnnotationApparmor] = infraSpec.Annotations[define.InspectAnnotationApparmor]
		}
	}
	return runtimeSpec, s, options, err
}
