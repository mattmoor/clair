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

package pgsql

import (
	"database/sql"
	"time"

	"github.com/coreos/clair/services"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/guregu/null/zero"
	"github.com/pborman/uuid"
)

// notificationz implements notifications.Service
type notificationz struct {
	*pgSQL
}

// CreateNotification from the vulnerability change.
func (pgSQL *notificationz) CreateNotification(oldVulnerability, newVulnerability services.Model) error {
	defer observeQueryTime("createNotification", "all", time.Now())

	// Insert Notification.
	oldVulnerabilityNullableID := sql.NullInt64{Int64: int64(oldVulnerability.ID), Valid: oldVulnerability.ID != 0}
	newVulnerabilityNullableID := sql.NullInt64{Int64: int64(newVulnerability.ID), Valid: newVulnerability.ID != 0}
	_, err := pgSQL.Exec(insertNotification, uuid.New(), oldVulnerabilityNullableID, newVulnerabilityNullableID)
	if err != nil {
		return handleError("CreateNotification", err)
	}

	return nil
}

// Get one available notification name (!locked && !deleted && (!notified || notified_but_timed-out)).
// Does not fill new/old vuln.
func (pgSQL *notificationz) GetAvailableNotification(renotifyInterval time.Duration) (services.VulnerabilityNotification, error) {
	defer observeQueryTime("GetAvailableNotification", "all", time.Now())

	before := time.Now().Add(-renotifyInterval)
	row := pgSQL.QueryRow(searchNotificationAvailable, before)
	notification, err := pgSQL.scanNotification(row, false)

	return notification, handleError("searchNotificationAvailable", err)
}

func (pgSQL *notificationz) GetNotification(name string) (services.VulnerabilityNotification, error) {
	defer observeQueryTime("GetNotification", "all", time.Now())

	// Get Notification.
	notification, err := pgSQL.scanNotification(pgSQL.QueryRow(searchNotification, name), true)
	if err != nil {
		return notification, handleError("searchNotification", err)
	}

	return notification, nil
}

func (pgSQL *notificationz) scanNotification(row *sql.Row, hasVulns bool) (notification services.VulnerabilityNotification, err error) {
	var created zero.Time
	var notified zero.Time
	var deleted zero.Time
	var oldVulnerabilityNullableID sql.NullInt64
	var newVulnerabilityNullableID sql.NullInt64

	// Scan notification.  Depending on whether hasVulns is true, the row contains a different number of columns.
	if hasVulns {
		err = row.Scan(
			&notification.ID,
			&notification.Name,
			&created,
			&notified,
			&deleted,
			&oldVulnerabilityNullableID,
			&newVulnerabilityNullableID,
		)
	} else {
		err = row.Scan(
			&notification.ID,
			&notification.Name,
			&created,
			&notified,
			&deleted,
		)
	}
	if err != nil {
		return notification, err
	}

	notification.Created = created.Time
	notification.Notified = notified.Time
	notification.Deleted = deleted.Time

	if hasVulns {
		if oldVulnerabilityNullableID.Valid {
			notification.OldVulnerability = &services.Vulnerability{Model: services.Model{int(oldVulnerabilityNullableID.Int64)}}
		}
		if newVulnerabilityNullableID.Valid {
			notification.NewVulnerability = &services.Vulnerability{Model: services.Model{int(newVulnerabilityNullableID.Int64)}}
		}
	}

	return notification, nil
}

func (pgSQL *notificationz) SetNotificationNotified(name string) error {
	defer observeQueryTime("SetNotificationNotified", "all", time.Now())

	if _, err := pgSQL.Exec(updatedNotificationNotified, name); err != nil {
		return handleError("updatedNotificationNotified", err)
	}
	return nil
}

func (pgSQL *notificationz) DeleteNotification(name string) error {
	defer observeQueryTime("DeleteNotification", "all", time.Now())

	result, err := pgSQL.Exec(removeNotification, name)
	if err != nil {
		return handleError("removeNotification", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return handleError("removeNotification.RowsAffected()", err)
	}

	if affected <= 0 {
		return cerrors.ErrNotFound
	}

	return nil
}
