// Code generated by mockery v2.53.3. DO NOT EDIT.

package v1

import (
	http "net/http"

	mock "github.com/stretchr/testify/mock"
)

// responseHandler is an autogenerated mock type for the responseHandler type
type responseHandler struct {
	mock.Mock
}

// Execute provides a mock function with given fields: code, resp
func (_m *responseHandler) Execute(code int, resp *http.Response) ([]byte, error) {
	ret := _m.Called(code, resp)

	if len(ret) == 0 {
		panic("no return value specified for Execute")
	}

	var r0 []byte
	var r1 error
	if rf, ok := ret.Get(0).(func(int, *http.Response) ([]byte, error)); ok {
		return rf(code, resp)
	}
	if rf, ok := ret.Get(0).(func(int, *http.Response) []byte); ok {
		r0 = rf(code, resp)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func(int, *http.Response) error); ok {
		r1 = rf(code, resp)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// newResponseHandler creates a new instance of responseHandler. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newResponseHandler(t interface {
	mock.TestingT
	Cleanup(func())
}) *responseHandler {
	mock := &responseHandler{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
