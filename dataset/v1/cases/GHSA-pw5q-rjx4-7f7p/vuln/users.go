// Source: https://github.com/getarcaneapp/arcane
// Ref: 97b9e9c83053ee9d78d23a4bf572defb19665721 Path: backend/api/handlers/users.go
// Excerpted and modified from https://github.com/getarcaneapp/arcane@97b9e9c83053ee9d78d23a4bf572defb19665721 on 2026-10-20
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

	updatedUser, err := h.userService.UpdateUser(ctx, userModel)
	if err != nil {
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
// ... lines 316-317 omitted ...
func (h *UserHandler) DeleteUser(ctx context.Context, input *DeleteUserInput) (*DeleteUserOutput, error) {
	if err := h.userService.DeleteUser(ctx, input.UserID); err != nil {
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
