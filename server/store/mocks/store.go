// Code generated by mockery v2.14.0. DO NOT EDIT.

package mocks

import (
	io "io"

	mock "github.com/stretchr/testify/mock"
	model "github.com/woodpecker-ci/woodpecker/server/model"
)

// Store is an autogenerated mock type for the Store type
type Store struct {
	mock.Mock
}

// Close provides a mock function with given fields:
func (_m *Store) Close() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ConfigCreate provides a mock function with given fields: _a0
func (_m *Store) ConfigCreate(_a0 *model.Config) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Config) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ConfigFindApproved provides a mock function with given fields: _a0
func (_m *Store) ConfigFindApproved(_a0 *model.Config) (bool, error) {
	ret := _m.Called(_a0)

	var r0 bool
	if rf, ok := ret.Get(0).(func(*model.Config) bool); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Config) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ConfigFindIdentical provides a mock function with given fields: repoID, hash
func (_m *Store) ConfigFindIdentical(repoID int64, hash string) (*model.Config, error) {
	ret := _m.Called(repoID, hash)

	var r0 *model.Config
	if rf, ok := ret.Get(0).(func(int64, string) *model.Config); ok {
		r0 = rf(repoID, hash)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Config)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(int64, string) error); ok {
		r1 = rf(repoID, hash)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ConfigsForPipeline provides a mock function with given fields: pipelineID
func (_m *Store) ConfigsForPipeline(pipelineID int64) ([]*model.Config, error) {
	ret := _m.Called(pipelineID)

	var r0 []*model.Config
	if rf, ok := ret.Get(0).(func(int64) []*model.Config); ok {
		r0 = rf(pipelineID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Config)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(int64) error); ok {
		r1 = rf(pipelineID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreatePipeline provides a mock function with given fields: _a0, _a1
func (_m *Store) CreatePipeline(_a0 *model.Pipeline, _a1 ...*model.Proc) error {
	_va := make([]interface{}, len(_a1))
	for _i := range _a1 {
		_va[_i] = _a1[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, _a0)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Pipeline, ...*model.Proc) error); ok {
		r0 = rf(_a0, _a1...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CreateRedirection provides a mock function with given fields: redirection
func (_m *Store) CreateRedirection(redirection *model.Redirection) error {
	ret := _m.Called(redirection)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Redirection) error); ok {
		r0 = rf(redirection)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CreateRepo provides a mock function with given fields: _a0
func (_m *Store) CreateRepo(_a0 *model.Repo) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Repo) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CreateUser provides a mock function with given fields: _a0
func (_m *Store) CreateUser(_a0 *model.User) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.User) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CronCreate provides a mock function with given fields: _a0
func (_m *Store) CronCreate(_a0 *model.Cron) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Cron) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CronDelete provides a mock function with given fields: _a0, _a1
func (_m *Store) CronDelete(_a0 *model.Repo, _a1 int64) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Repo, int64) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CronFind provides a mock function with given fields: _a0, _a1
func (_m *Store) CronFind(_a0 *model.Repo, _a1 int64) (*model.Cron, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *model.Cron
	if rf, ok := ret.Get(0).(func(*model.Repo, int64) *model.Cron); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Cron)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Repo, int64) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CronGetLock provides a mock function with given fields: _a0, _a1
func (_m *Store) CronGetLock(_a0 *model.Cron, _a1 int64) (bool, error) {
	ret := _m.Called(_a0, _a1)

	var r0 bool
	if rf, ok := ret.Get(0).(func(*model.Cron, int64) bool); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Cron, int64) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CronList provides a mock function with given fields: _a0
func (_m *Store) CronList(_a0 *model.Repo) ([]*model.Cron, error) {
	ret := _m.Called(_a0)

	var r0 []*model.Cron
	if rf, ok := ret.Get(0).(func(*model.Repo) []*model.Cron); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Cron)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Repo) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CronListNextExecute provides a mock function with given fields: _a0, _a1
func (_m *Store) CronListNextExecute(_a0 int64, _a1 int64) ([]*model.Cron, error) {
	ret := _m.Called(_a0, _a1)

	var r0 []*model.Cron
	if rf, ok := ret.Get(0).(func(int64, int64) []*model.Cron); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Cron)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(int64, int64) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CronUpdate provides a mock function with given fields: _a0, _a1
func (_m *Store) CronUpdate(_a0 *model.Repo, _a1 *model.Cron) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Repo, *model.Cron) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteRepo provides a mock function with given fields: _a0
func (_m *Store) DeleteRepo(_a0 *model.Repo) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Repo) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteUser provides a mock function with given fields: _a0
func (_m *Store) DeleteUser(_a0 *model.User) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.User) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FileCreate provides a mock function with given fields: _a0, _a1
func (_m *Store) FileCreate(_a0 *model.File, _a1 io.Reader) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.File, io.Reader) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FileFind provides a mock function with given fields: _a0, _a1
func (_m *Store) FileFind(_a0 *model.Proc, _a1 string) (*model.File, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *model.File
	if rf, ok := ret.Get(0).(func(*model.Proc, string) *model.File); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.File)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Proc, string) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FileList provides a mock function with given fields: _a0
func (_m *Store) FileList(_a0 *model.Pipeline) ([]*model.File, error) {
	ret := _m.Called(_a0)

	var r0 []*model.File
	if rf, ok := ret.Get(0).(func(*model.Pipeline) []*model.File); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.File)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Pipeline) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FileRead provides a mock function with given fields: _a0, _a1
func (_m *Store) FileRead(_a0 *model.Proc, _a1 string) (io.ReadCloser, error) {
	ret := _m.Called(_a0, _a1)

	var r0 io.ReadCloser
	if rf, ok := ret.Get(0).(func(*model.Proc, string) io.ReadCloser); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(io.ReadCloser)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Proc, string) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetActivePipelineList provides a mock function with given fields: repo, page
func (_m *Store) GetActivePipelineList(repo *model.Repo, page int) ([]*model.Pipeline, error) {
	ret := _m.Called(repo, page)

	var r0 []*model.Pipeline
	if rf, ok := ret.Get(0).(func(*model.Repo, int) []*model.Pipeline); ok {
		r0 = rf(repo, page)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Pipeline)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Repo, int) error); ok {
		r1 = rf(repo, page)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPipeline provides a mock function with given fields: _a0
func (_m *Store) GetPipeline(_a0 int64) (*model.Pipeline, error) {
	ret := _m.Called(_a0)

	var r0 *model.Pipeline
	if rf, ok := ret.Get(0).(func(int64) *model.Pipeline); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Pipeline)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(int64) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPipelineCommit provides a mock function with given fields: _a0, _a1, _a2
func (_m *Store) GetPipelineCommit(_a0 *model.Repo, _a1 string, _a2 string) (*model.Pipeline, error) {
	ret := _m.Called(_a0, _a1, _a2)

	var r0 *model.Pipeline
	if rf, ok := ret.Get(0).(func(*model.Repo, string, string) *model.Pipeline); ok {
		r0 = rf(_a0, _a1, _a2)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Pipeline)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Repo, string, string) error); ok {
		r1 = rf(_a0, _a1, _a2)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPipelineCount provides a mock function with given fields:
func (_m *Store) GetPipelineCount() (int64, error) {
	ret := _m.Called()

	var r0 int64
	if rf, ok := ret.Get(0).(func() int64); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int64)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPipelineLast provides a mock function with given fields: _a0, _a1
func (_m *Store) GetPipelineLast(_a0 *model.Repo, _a1 string) (*model.Pipeline, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *model.Pipeline
	if rf, ok := ret.Get(0).(func(*model.Repo, string) *model.Pipeline); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Pipeline)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Repo, string) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPipelineLastBefore provides a mock function with given fields: _a0, _a1, _a2
func (_m *Store) GetPipelineLastBefore(_a0 *model.Repo, _a1 string, _a2 int64) (*model.Pipeline, error) {
	ret := _m.Called(_a0, _a1, _a2)

	var r0 *model.Pipeline
	if rf, ok := ret.Get(0).(func(*model.Repo, string, int64) *model.Pipeline); ok {
		r0 = rf(_a0, _a1, _a2)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Pipeline)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Repo, string, int64) error); ok {
		r1 = rf(_a0, _a1, _a2)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPipelineList provides a mock function with given fields: _a0, _a1
func (_m *Store) GetPipelineList(_a0 *model.Repo, _a1 int) ([]*model.Pipeline, error) {
	ret := _m.Called(_a0, _a1)

	var r0 []*model.Pipeline
	if rf, ok := ret.Get(0).(func(*model.Repo, int) []*model.Pipeline); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Pipeline)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Repo, int) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPipelineNumber provides a mock function with given fields: _a0, _a1
func (_m *Store) GetPipelineNumber(_a0 *model.Repo, _a1 int64) (*model.Pipeline, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *model.Pipeline
	if rf, ok := ret.Get(0).(func(*model.Repo, int64) *model.Pipeline); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Pipeline)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Repo, int64) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPipelineQueue provides a mock function with given fields:
func (_m *Store) GetPipelineQueue() ([]*model.Feed, error) {
	ret := _m.Called()

	var r0 []*model.Feed
	if rf, ok := ret.Get(0).(func() []*model.Feed); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Feed)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetPipelineRef provides a mock function with given fields: _a0, _a1
func (_m *Store) GetPipelineRef(_a0 *model.Repo, _a1 string) (*model.Pipeline, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *model.Pipeline
	if rf, ok := ret.Get(0).(func(*model.Repo, string) *model.Pipeline); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Pipeline)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Repo, string) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetRedirection provides a mock function with given fields: _a0
func (_m *Store) GetRedirection(_a0 string) (*model.Redirection, error) {
	ret := _m.Called(_a0)

	var r0 *model.Redirection
	if rf, ok := ret.Get(0).(func(string) *model.Redirection); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Redirection)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetRepo provides a mock function with given fields: _a0
func (_m *Store) GetRepo(_a0 int64) (*model.Repo, error) {
	ret := _m.Called(_a0)

	var r0 *model.Repo
	if rf, ok := ret.Get(0).(func(int64) *model.Repo); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Repo)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(int64) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetRepoCount provides a mock function with given fields:
func (_m *Store) GetRepoCount() (int64, error) {
	ret := _m.Called()

	var r0 int64
	if rf, ok := ret.Get(0).(func() int64); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int64)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetRepoName provides a mock function with given fields: _a0
func (_m *Store) GetRepoName(_a0 string) (*model.Repo, error) {
	ret := _m.Called(_a0)

	var r0 *model.Repo
	if rf, ok := ret.Get(0).(func(string) *model.Repo); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Repo)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetRepoNameFallback provides a mock function with given fields: remoteID, fullName
func (_m *Store) GetRepoNameFallback(remoteID model.RemoteID, fullName string) (*model.Repo, error) {
	ret := _m.Called(remoteID, fullName)

	var r0 *model.Repo
	if rf, ok := ret.Get(0).(func(model.RemoteID, string) *model.Repo); ok {
		r0 = rf(remoteID, fullName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Repo)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(model.RemoteID, string) error); ok {
		r1 = rf(remoteID, fullName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetRepoRemoteID provides a mock function with given fields: _a0
func (_m *Store) GetRepoRemoteID(_a0 model.RemoteID) (*model.Repo, error) {
	ret := _m.Called(_a0)

	var r0 *model.Repo
	if rf, ok := ret.Get(0).(func(model.RemoteID) *model.Repo); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Repo)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(model.RemoteID) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUser provides a mock function with given fields: _a0
func (_m *Store) GetUser(_a0 int64) (*model.User, error) {
	ret := _m.Called(_a0)

	var r0 *model.User
	if rf, ok := ret.Get(0).(func(int64) *model.User); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.User)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(int64) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUserCount provides a mock function with given fields:
func (_m *Store) GetUserCount() (int64, error) {
	ret := _m.Called()

	var r0 int64
	if rf, ok := ret.Get(0).(func() int64); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int64)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUserList provides a mock function with given fields:
func (_m *Store) GetUserList() ([]*model.User, error) {
	ret := _m.Called()

	var r0 []*model.User
	if rf, ok := ret.Get(0).(func() []*model.User); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.User)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUserLogin provides a mock function with given fields: _a0
func (_m *Store) GetUserLogin(_a0 string) (*model.User, error) {
	ret := _m.Called(_a0)

	var r0 *model.User
	if rf, ok := ret.Get(0).(func(string) *model.User); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.User)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GlobalSecretFind provides a mock function with given fields: _a0
func (_m *Store) GlobalSecretFind(_a0 string) (*model.Secret, error) {
	ret := _m.Called(_a0)

	var r0 *model.Secret
	if rf, ok := ret.Get(0).(func(string) *model.Secret); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Secret)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GlobalSecretList provides a mock function with given fields:
func (_m *Store) GlobalSecretList() ([]*model.Secret, error) {
	ret := _m.Called()

	var r0 []*model.Secret
	if rf, ok := ret.Get(0).(func() []*model.Secret); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Secret)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// HasRedirectionForRepo provides a mock function with given fields: _a0, _a1
func (_m *Store) HasRedirectionForRepo(_a0 int64, _a1 string) (bool, error) {
	ret := _m.Called(_a0, _a1)

	var r0 bool
	if rf, ok := ret.Get(0).(func(int64, string) bool); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(int64, string) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LogFind provides a mock function with given fields: _a0
func (_m *Store) LogFind(_a0 *model.Proc) (io.ReadCloser, error) {
	ret := _m.Called(_a0)

	var r0 io.ReadCloser
	if rf, ok := ret.Get(0).(func(*model.Proc) io.ReadCloser); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(io.ReadCloser)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Proc) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LogSave provides a mock function with given fields: _a0, _a1
func (_m *Store) LogSave(_a0 *model.Proc, _a1 io.Reader) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Proc, io.Reader) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Migrate provides a mock function with given fields:
func (_m *Store) Migrate() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// OrgSecretFind provides a mock function with given fields: _a0, _a1
func (_m *Store) OrgSecretFind(_a0 string, _a1 string) (*model.Secret, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *model.Secret
	if rf, ok := ret.Get(0).(func(string, string) *model.Secret); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Secret)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// OrgSecretList provides a mock function with given fields: _a0
func (_m *Store) OrgSecretList(_a0 string) ([]*model.Secret, error) {
	ret := _m.Called(_a0)

	var r0 []*model.Secret
	if rf, ok := ret.Get(0).(func(string) []*model.Secret); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Secret)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PermDelete provides a mock function with given fields: perm
func (_m *Store) PermDelete(perm *model.Perm) error {
	ret := _m.Called(perm)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Perm) error); ok {
		r0 = rf(perm)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PermFind provides a mock function with given fields: user, repo
func (_m *Store) PermFind(user *model.User, repo *model.Repo) (*model.Perm, error) {
	ret := _m.Called(user, repo)

	var r0 *model.Perm
	if rf, ok := ret.Get(0).(func(*model.User, *model.Repo) *model.Perm); ok {
		r0 = rf(user, repo)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Perm)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.User, *model.Repo) error); ok {
		r1 = rf(user, repo)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PermFlush provides a mock function with given fields: user, before
func (_m *Store) PermFlush(user *model.User, before int64) error {
	ret := _m.Called(user, before)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.User, int64) error); ok {
		r0 = rf(user, before)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PermUpsert provides a mock function with given fields: perm
func (_m *Store) PermUpsert(perm *model.Perm) error {
	ret := _m.Called(perm)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Perm) error); ok {
		r0 = rf(perm)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Ping provides a mock function with given fields:
func (_m *Store) Ping() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PipelineConfigCreate provides a mock function with given fields: _a0
func (_m *Store) PipelineConfigCreate(_a0 *model.PipelineConfig) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.PipelineConfig) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ProcChild provides a mock function with given fields: _a0, _a1, _a2
func (_m *Store) ProcChild(_a0 *model.Pipeline, _a1 int, _a2 string) (*model.Proc, error) {
	ret := _m.Called(_a0, _a1, _a2)

	var r0 *model.Proc
	if rf, ok := ret.Get(0).(func(*model.Pipeline, int, string) *model.Proc); ok {
		r0 = rf(_a0, _a1, _a2)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Proc)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Pipeline, int, string) error); ok {
		r1 = rf(_a0, _a1, _a2)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ProcClear provides a mock function with given fields: _a0
func (_m *Store) ProcClear(_a0 *model.Pipeline) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Pipeline) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ProcCreate provides a mock function with given fields: _a0
func (_m *Store) ProcCreate(_a0 []*model.Proc) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func([]*model.Proc) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ProcFind provides a mock function with given fields: _a0, _a1
func (_m *Store) ProcFind(_a0 *model.Pipeline, _a1 int) (*model.Proc, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *model.Proc
	if rf, ok := ret.Get(0).(func(*model.Pipeline, int) *model.Proc); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Proc)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Pipeline, int) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ProcList provides a mock function with given fields: _a0
func (_m *Store) ProcList(_a0 *model.Pipeline) ([]*model.Proc, error) {
	ret := _m.Called(_a0)

	var r0 []*model.Proc
	if rf, ok := ret.Get(0).(func(*model.Pipeline) []*model.Proc); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Proc)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Pipeline) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ProcLoad provides a mock function with given fields: _a0
func (_m *Store) ProcLoad(_a0 int64) (*model.Proc, error) {
	ret := _m.Called(_a0)

	var r0 *model.Proc
	if rf, ok := ret.Get(0).(func(int64) *model.Proc); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Proc)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(int64) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ProcUpdate provides a mock function with given fields: _a0
func (_m *Store) ProcUpdate(_a0 *model.Proc) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Proc) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RegistryCreate provides a mock function with given fields: _a0
func (_m *Store) RegistryCreate(_a0 *model.Registry) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Registry) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RegistryDelete provides a mock function with given fields: repo, addr
func (_m *Store) RegistryDelete(repo *model.Repo, addr string) error {
	ret := _m.Called(repo, addr)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Repo, string) error); ok {
		r0 = rf(repo, addr)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RegistryFind provides a mock function with given fields: _a0, _a1
func (_m *Store) RegistryFind(_a0 *model.Repo, _a1 string) (*model.Registry, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *model.Registry
	if rf, ok := ret.Get(0).(func(*model.Repo, string) *model.Registry); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Registry)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Repo, string) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RegistryList provides a mock function with given fields: _a0
func (_m *Store) RegistryList(_a0 *model.Repo) ([]*model.Registry, error) {
	ret := _m.Called(_a0)

	var r0 []*model.Registry
	if rf, ok := ret.Get(0).(func(*model.Repo) []*model.Registry); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Registry)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Repo) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RegistryUpdate provides a mock function with given fields: _a0
func (_m *Store) RegistryUpdate(_a0 *model.Registry) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Registry) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RepoBatch provides a mock function with given fields: _a0
func (_m *Store) RepoBatch(_a0 []*model.Repo) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func([]*model.Repo) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RepoList provides a mock function with given fields: user, owned
func (_m *Store) RepoList(user *model.User, owned bool) ([]*model.Repo, error) {
	ret := _m.Called(user, owned)

	var r0 []*model.Repo
	if rf, ok := ret.Get(0).(func(*model.User, bool) []*model.Repo); ok {
		r0 = rf(user, owned)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Repo)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.User, bool) error); ok {
		r1 = rf(user, owned)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RepoListLatest provides a mock function with given fields: _a0
func (_m *Store) RepoListLatest(_a0 *model.User) ([]*model.Feed, error) {
	ret := _m.Called(_a0)

	var r0 []*model.Feed
	if rf, ok := ret.Get(0).(func(*model.User) []*model.Feed); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Feed)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.User) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SecretCreate provides a mock function with given fields: _a0
func (_m *Store) SecretCreate(_a0 *model.Secret) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Secret) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SecretDelete provides a mock function with given fields: _a0
func (_m *Store) SecretDelete(_a0 *model.Secret) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Secret) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SecretFind provides a mock function with given fields: _a0, _a1
func (_m *Store) SecretFind(_a0 *model.Repo, _a1 string) (*model.Secret, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *model.Secret
	if rf, ok := ret.Get(0).(func(*model.Repo, string) *model.Secret); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Secret)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Repo, string) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SecretList provides a mock function with given fields: _a0, _a1
func (_m *Store) SecretList(_a0 *model.Repo, _a1 bool) ([]*model.Secret, error) {
	ret := _m.Called(_a0, _a1)

	var r0 []*model.Secret
	if rf, ok := ret.Get(0).(func(*model.Repo, bool) []*model.Secret); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Secret)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Repo, bool) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SecretUpdate provides a mock function with given fields: _a0
func (_m *Store) SecretUpdate(_a0 *model.Secret) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Secret) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ServerConfigGet provides a mock function with given fields: _a0
func (_m *Store) ServerConfigGet(_a0 string) (string, error) {
	ret := _m.Called(_a0)

	var r0 string
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ServerConfigSet provides a mock function with given fields: _a0, _a1
func (_m *Store) ServerConfigSet(_a0 string, _a1 string) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TaskDelete provides a mock function with given fields: _a0
func (_m *Store) TaskDelete(_a0 string) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TaskInsert provides a mock function with given fields: _a0
func (_m *Store) TaskInsert(_a0 *model.Task) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Task) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TaskList provides a mock function with given fields:
func (_m *Store) TaskList() ([]*model.Task, error) {
	ret := _m.Called()

	var r0 []*model.Task
	if rf, ok := ret.Get(0).(func() []*model.Task); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Task)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdatePipeline provides a mock function with given fields: _a0
func (_m *Store) UpdatePipeline(_a0 *model.Pipeline) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Pipeline) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateRepo provides a mock function with given fields: _a0
func (_m *Store) UpdateRepo(_a0 *model.Repo) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Repo) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateUser provides a mock function with given fields: _a0
func (_m *Store) UpdateUser(_a0 *model.User) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.User) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UserFeed provides a mock function with given fields: _a0
func (_m *Store) UserFeed(_a0 *model.User) ([]*model.Feed, error) {
	ret := _m.Called(_a0)

	var r0 []*model.Feed
	if rf, ok := ret.Get(0).(func(*model.User) []*model.Feed); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Feed)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.User) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

type mockConstructorTestingTNewStore interface {
	mock.TestingT
	Cleanup(func())
}

// NewStore creates a new instance of Store. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewStore(t mockConstructorTestingTNewStore) *Store {
	mock := &Store{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
