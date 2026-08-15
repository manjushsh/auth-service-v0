package auth

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Credentials
}

type RegisterResponse struct {
	Status string `json:"status"`
	Email  string `json:"email"`
}

type GenerateCodeRequest struct {
	Credentials
	RedirectURI string `json:"redirect_uri"`
}

type GenerateCodeResponse struct {
	Code        string `json:"code"`
	RedirectURL string `json:"redirect_url,omitempty"`
}

type ExchangeTokenRequest struct {
	Code string `json:"code"`
	// RedirectURI must match the redirect_uri the code was issued for
	// (empty when the code was issued without one).
	RedirectURI string `json:"redirect_uri"`
}

type ExchangeTokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
}

type IntrospectResponse struct {
	Active    bool   `json:"active"`
	Subject   string `json:"sub,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
}

// PasswordResetRequest redeems an admin-issued reset token. Unauthenticated:
// the token is the credential.
type PasswordResetRequest struct {
	ResetToken  string `json:"reset_token"`
	NewPassword string `json:"new_password"`
}
