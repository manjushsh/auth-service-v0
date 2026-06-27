package basic

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Credentials
}

type LoginRequest struct {
	Credentials
}

type RegisterResponse struct {
	Status string `json:"status"`
	Email  string `json:"email"`
}

type LoginResponse struct {
	Status string `json:"status"`
}
