package server

type Result struct {

	// HTTP response code
	Code int `json:"code"`

	// HTTP Result string - normally one of OK | Error
	Result string `json:"result"`

	// The request message being returned
	Message interface{} `json:"message"`
}
