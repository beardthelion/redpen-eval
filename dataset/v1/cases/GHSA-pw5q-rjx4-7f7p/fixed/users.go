// Source: https://github.com/getarcaneapp/arcane
// Ref: 21ea962f86d967dac8ae02a050f6e5f043d10fa1 Path: backend/api/handlers/users.go
// Excerpted and modified from https://github.com/getarcaneapp/arcane@21ea962f86d967dac8ae02a050f6e5f043d10fa1 on 2026-10-20
// License: BSD-3-Clause, see licenses/getarcaneapp__arcane/LICENSE
// Copyright (c) 2025, Kyle Mendell
func (h *UserHandler) UpdateUser(ctx context.Context, input *UpdateUserInput) (*UpdateUserOutput, error) {
	userModel, err := h.userService.GetUserByID(ctx, input.UserID)
	if err != nil {
		return nil, huma.Error404NotFound("User not found")
	}

	normalizedEmail, err := normalizeOptionalEmailInternal(input.Body.Email)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	input.Body.Email = normalizedEmail

	if input.Body.Username != nil {
		userModel.Username = *input.Body.Username
	}
	if input.Body.DisplayName != nil {
		userModel.DisplayName = input.Body.DisplayName
	}
	if input.Body.Email != nil {
		userModel.Email = input.Body.Email
	}
	if input.Body.Locale != nil {
		userModel.Locale = input.Body.Locale
	}
	if input.Body.TimeFormat != nil {
		userModel.TimeFormat = *input.Body.TimeFormat
	}

	if input.Body.Password != nil && *input.Body.Password != "" {
		hashedPassword, err := h.userService.HashPassword(*input.Body.Password)
		if err != nil {
			return nil, huma.Error500InternalServerError("Failed to hash password")
		}
		userModel.PasswordHash = hashedPassword
	}

	userModel.UpdatedAt = new(time.Now())

	// Privilege ordering: a non-admin caller may not modify a global admin
	// target, nor set another user's password. The service re-enforces the
	// target-admin check.
	callerPerms, _ := humamw.PermissionsFromContext(ctx)
	caller, _ := humamw.GetCurrentUserFromContext(ctx)
	if callerPerms != nil && !callerPerms.IsGlobalAdmin() {
		if input.Body.Password != nil && *input.Body.Password != "" && caller != nil && caller.ID != userModel.ID {
			return nil, huma.Error403Forbidden(services.ErrInsufficientPrivilege.Error())
		}
		targetPerms, err := h.userService.ResolveUserPermissions(ctx, userModel.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("Failed to resolve target permissions")
		}
		if targetPerms != nil && targetPerms.IsGlobalAdmin() {
			return nil, huma.Error403Forbidden(services.ErrInsufficientPrivilege.Error())
		}
	}

	updatedUser, err := h.userService.UpdateUser(ctx, userModel, callerPerms)
	if err != nil {
		if errors.Is(err, services.ErrInsufficientPrivilege) {
			return nil, huma.Error403Forbidden(services.ErrInsufficientPrivilege.Error())
		}
		if errors.Is(err, services.ErrCannotRemoveLastAdmin) {
			return nil, huma.Error409Conflict(services.ErrCannotRemoveLastAdmin.Error())
		}
		if errors.Is(err, services.ErrUserNotFound) {
			return nil, huma.Error404NotFound("User not found")
		}
		return nil, huma.Error500InternalServerError("Failed to update user")
	}

	if h.authService != nil {
		h.authService.InvalidateUserTokenCache(updatedUser.ID)
	}

	out, err := h.userService.ToUserResponseDto(ctx, *updatedUser)
	if err != nil {
		return nil, huma.Error500InternalServerError("Failed to map user")
	}

	return &UpdateUserOutput{
		Body: base.ApiResponse[user.User]{
			Success: true,
			Data:    out,
		},
	}, nil
}
// ... lines 337-338 omitted ...
func (h *UserHandler) DeleteUser(ctx context.Context, input *DeleteUserInput) (*DeleteUserOutput, error) {
	// Privilege ordering: a non-admin caller may not delete a global admin
	// target. The service enforces the same check; this pre-check produces a
	// clean 403 without entering the delete path.
	callerPerms, _ := humamw.PermissionsFromContext(ctx)
	caller, _ := humamw.GetCurrentUserFromContext(ctx)
	if callerPerms != nil && !callerPerms.IsGlobalAdmin() && caller != nil && caller.ID != input.UserID {
		targetPerms, err := h.userService.ResolveUserPermissions(ctx, input.UserID)
		if err != nil {
			return nil, huma.Error500InternalServerError("Failed to resolve target permissions")
		}
		if targetPerms != nil && targetPerms.IsGlobalAdmin() {
			return nil, huma.Error403Forbidden(services.ErrInsufficientPrivilege.Error())
		}
	}

	if err := h.userService.DeleteUser(ctx, input.UserID, callerPerms); err != nil {
		if errors.Is(err, services.ErrInsufficientPrivilege) {
			return nil, huma.Error403Forbidden(services.ErrInsufficientPrivilege.Error())
		}
		if errors.Is(err, services.ErrCannotRemoveLastAdmin) {
			return nil, huma.Error409Conflict(services.ErrCannotRemoveLastAdmin.Error())
		}
		if errors.Is(err, services.ErrUserNotFound) {
			return nil, huma.Error404NotFound("User not found")
		}
		return nil, huma.Error500InternalServerError("Failed to delete user")
	}

	if h.authService != nil {
		h.authService.InvalidateUserTokenCache(input.UserID)
	}

	return &DeleteUserOutput{
		Body: base.ApiResponse[base.MessageResponse]{
			Success: true,
			Data: base.MessageResponse{
				Message: "User deleted successfully",
			},
		},
	}, nil
}
