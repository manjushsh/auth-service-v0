package auth

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserRecord struct {
	ID           string
	PasswordHash string
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
}

type ExchangeTokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
}

type IntrospectRequest struct {
	Token string `json:"token"`
}

type IntrospectResponse struct {
	Active    bool   `json:"active"`
	Subject   string `json:"sub,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
}
