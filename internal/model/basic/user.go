package basic

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterResponse struct {
	Status string `json:"status"`
	Email  string `json:"email"`
}

type LoginResponse struct {
	Status string `json:"status"`
}
