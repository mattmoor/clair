// Copyright 2015 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package notifications defines an interface for interacting with notification state.
package notifications

import (
	"fmt"
	"time"

	"github.com/coreos/clair/config"
	"github.com/coreos/clair/services"
)

type Driver func(cfg config.RegistrableComponentConfig) (Service, error)

var notificationDrivers = make(map[string]Driver)

// Register makes a Service constructor available by the provided name.
//
// If this function is called twice with the same name or if the Constructor is
// nil, it panics.
func Register(name string, driver Driver) {
	if driver == nil {
		panic("notifications: could not register nil Driver")
	}
	if _, dup := notificationDrivers[name]; dup {
		panic("notifications: could not register duplicate Driver: " + name)
	}
	notificationDrivers[name] = driver
}

// Open opens a Datastore specified by a configuration.
func Open(cfg config.RegistrableComponentConfig) (ls Service, err error) {
	driver, ok := notificationDrivers[cfg.Type]
	if !ok {
		err = fmt.Errorf("notifications: unknown Driver %q (forgotten configuration or import?)", cfg.Type)
		return
	}
	return driver(cfg)
}

type Service interface {
	services.Base
	// # Notification
	// GetAvailableNotification returns the Name, Created, Notified and Deleted fields of a
	// Notification that should be handled. The renotify interval defines how much time after being
	// marked as Notified by SetNotificationNotified, a Notification that hasn't been deleted should
	// be returned again by this function. A Notification for which there is a valid Lock with the
	// same Name should not be returned.
	GetAvailableNotification(renotifyInterval time.Duration) (services.VulnerabilityNotification, error)

	// GetNotification returns a Notification.
	// OldVulnerability and NewVulnerability will have only their Model populated with the services.Model of
	// the Old/New Vulnerability respectively, but the burden of fetching these is on the caller of this API.
	GetNotification(name string) (services.VulnerabilityNotification, error)

	// SetNotificationNotified marks a Notification as notified and thus, makes it unavailable for
	// GetAvailableNotification, until the renotify duration is elapsed.
	SetNotificationNotified(name string) error

	// DeleteNotification marks a Notification as deleted, and thus, makes it unavailable for
	// GetAvailableNotification.
	DeleteNotification(name string) error

	// CreateNotification inserts a notification into the backing store with the change denoted by the old
	// and new vulnerability identifiers.
	CreateNotification(oldVulnerability, newVulnerability services.Model) error
}

type Null struct {
}

// Ping implements services.Base
func (n *Null) Ping() bool {
	return true
}

// Close implements services.Base
func (n *Null) Close() {}

// GetAvailableNotification implements Service
func (n *Null) GetAvailableNotification(renotifyInterval time.Duration) (services.VulnerabilityNotification, error) {
	return services.VulnerabilityNotification{}, services.ErrBackendException
}

// GetNotification implements Service
func (n *Null) GetNotification(name string) (services.VulnerabilityNotification, error) {
	return services.VulnerabilityNotification{}, services.ErrBackendException
}

// SetNotificationNotified implements Service
func (n *Null) SetNotificationNotified(name string) error {
	return services.ErrBackendException
}

// DeleteNotification implements Service
func (n *Null) DeleteNotification(name string) error {
	return services.ErrBackendException
}

// CreateNotification reads and discards the notification.
func (n *Null) CreateNotification(oldVulnerability, newVulnerability services.Model) error {
	return nil
}
