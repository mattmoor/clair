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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/coreos/clair/services"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/coreos/clair/utils/types"
)

func TestNotification(t *testing.T) {
	b, err := openDatabaseForTest("Notification", false)
	if err != nil {
		t.Error(err)
		return
	}
	defer b.Close()
	vulnz := &vulnz{&featurez{b, &ns{b}}}
	layerz := &layerz{&featurez{b, &ns{b}}}
	datastore := &notificationz{b}

	// Try to get a notification when there is none.
	_, err = datastore.GetAvailableNotification(time.Second)
	assert.Equal(t, cerrors.ErrNotFound, err)

	// Create some data.
	f1 := services.Feature{
		Name:      "TestNotificationFeature1",
		Namespace: services.Namespace{Name: "TestNotificationNamespace1"},
	}

	f2 := services.Feature{
		Name:      "TestNotificationFeature2",
		Namespace: services.Namespace{Name: "TestNotificationNamespace1"},
	}

	l1 := services.Layer{
		Name: "TestNotificationLayer1",
		Features: []services.FeatureVersion{
			{
				Feature: f1,
				Version: types.NewVersionUnsafe("0.1"),
			},
		},
	}

	l2 := services.Layer{
		Name: "TestNotificationLayer2",
		Features: []services.FeatureVersion{
			{
				Feature: f1,
				Version: types.NewVersionUnsafe("0.2"),
			},
		},
	}

	l3 := services.Layer{
		Name: "TestNotificationLayer3",
		Features: []services.FeatureVersion{
			{
				Feature: f1,
				Version: types.NewVersionUnsafe("0.3"),
			},
		},
	}

	l4 := services.Layer{
		Name: "TestNotificationLayer4",
		Features: []services.FeatureVersion{
			{
				Feature: f2,
				Version: types.NewVersionUnsafe("0.1"),
			},
		},
	}

	if !assert.Nil(t, layerz.InsertLayer(l1)) ||
		!assert.Nil(t, layerz.InsertLayer(l2)) ||
		!assert.Nil(t, layerz.InsertLayer(l3)) ||
		!assert.Nil(t, layerz.InsertLayer(l4)) {
		return
	}

	// Insert a new vulnerability that is introduced by three layers.
	v1 := services.Vulnerability{
		Name:        "TestNotificationVulnerability1",
		Namespace:   f1.Namespace,
		Description: "TestNotificationDescription1",
		Link:        "TestNotificationLink1",
		Severity:    "Unknown",
		FixedIn: []services.FeatureVersion{
			{
				Feature: f1,
				Version: types.NewVersionUnsafe("1.0"),
			},
		},
	}
	assert.Nil(t, vulnz.InsertVulnerabilities([]services.Vulnerability{v1}, datastore))

	// Refetch our expected vulnerability (including Model)
	v1, err = vulnz.FindVulnerability(v1.Namespace.Name, v1.Name)
	if !assert.Nil(t, err) {
		return
	}

	// Get the notification associated to the previously inserted vulnerability.
	notification, err := datastore.GetAvailableNotification(time.Second)

	if assert.Nil(t, err) && assert.NotEmpty(t, notification.Name) {
		// Verify the renotify behaviour.
		if assert.Nil(t, datastore.SetNotificationNotified(notification.Name)) {
			_, err := datastore.GetAvailableNotification(time.Second)
			assert.Equal(t, cerrors.ErrNotFound, err)

			time.Sleep(50 * time.Millisecond)
			notificationB, err := datastore.GetAvailableNotification(20 * time.Millisecond)
			assert.Nil(t, err)
			assert.Equal(t, notification.Name, notificationB.Name)

			datastore.SetNotificationNotified(notification.Name)
		}

		page := services.VulnerabilityNotificationFirstPage

		// Get notification.
		filledNotification, err := datastore.GetNotification(notification.Name)
		if assert.Nil(t, err) {
			assert.Nil(t, filledNotification.OldVulnerability)

			if assert.NotNil(t, filledNotification.NewVulnerability) {
				assert.Equal(t, v1.Model, filledNotification.NewVulnerability.Model)
				vulnerability, err := vulnz.FindVulnerabilityByID(filledNotification.NewVulnerability.Model)
				if assert.Nil(t, err) {
					filledNotification.NewVulnerability = &vulnerability
					page.NewVulnerability, err = layerz.LoadLayerIntroducingVulnerability(&vulnerability, 2, page.NewVulnerability)
					if assert.Nil(t, err) {
						assert.Len(t, vulnerability.LayersIntroducingVulnerability, 2)
						// Get second page
						page.NewVulnerability, err = layerz.LoadLayerIntroducingVulnerability(&vulnerability, 2, page.NewVulnerability)
						if assert.Nil(t, err) {
							assert.Len(t, vulnerability.LayersIntroducingVulnerability, 1)
						}
					}
				}
			}
		}

		// Delete notification.
		assert.Nil(t, datastore.DeleteNotification(notification.Name))

		_, err = datastore.GetAvailableNotification(time.Millisecond)
		assert.Equal(t, cerrors.ErrNotFound, err)
	}

	// Update a vulnerability and ensure that the old/new vulnerabilities are correct.
	v1b := v1
	v1b.Severity = types.High
	v1b.FixedIn = []services.FeatureVersion{
		{
			Feature: f1,
			Version: types.MinVersion,
		},
		{
			Feature: f2,
			Version: types.MaxVersion,
		},
	}

	if assert.Nil(t, vulnz.InsertVulnerabilities([]services.Vulnerability{v1b}, datastore)) {
		v1b, err = vulnz.FindVulnerability(v1.Namespace.Name, v1.Name)

		if assert.Nil(t, err) {
			notification, err = datastore.GetAvailableNotification(time.Second)
			assert.Nil(t, err)
			assert.NotEmpty(t, notification.Name)

			page := services.VulnerabilityNotificationFirstPage

			if assert.Nil(t, err) && assert.NotEmpty(t, notification.Name) {
				filledNotification, err := datastore.GetNotification(notification.Name)
				if assert.Nil(t, err) {
					if assert.NotNil(t, filledNotification.OldVulnerability) {
						assert.Equal(t, v1.Model, filledNotification.OldVulnerability.Model)
						vulnerability, err := vulnz.FindVulnerabilityByID(filledNotification.OldVulnerability.Model)
						if assert.Nil(t, err) {
							assert.Equal(t, v1.Severity, vulnerability.Severity)
							page.OldVulnerability, err = layerz.LoadLayerIntroducingVulnerability(&vulnerability, 2, page.OldVulnerability)
							if assert.Nil(t, err) {
								assert.Len(t, vulnerability.LayersIntroducingVulnerability, 2)
							}
						}
					}

					if assert.NotNil(t, filledNotification.NewVulnerability) {
						assert.Equal(t, v1b.Model, filledNotification.NewVulnerability.Model)
						vulnerability, err := vulnz.FindVulnerabilityByID(filledNotification.NewVulnerability.Model)
						if assert.Nil(t, err) {
							assert.Equal(t, v1b.Severity, vulnerability.Severity)
							page.NewVulnerability, err = layerz.LoadLayerIntroducingVulnerability(&vulnerability, 2, page.NewVulnerability)
							if assert.Nil(t, err) {

								assert.Len(t, vulnerability.LayersIntroducingVulnerability, 1)
							}
						}
					}

					assert.Equal(t, -1, page.NewVulnerability)
				}

				assert.Nil(t, datastore.DeleteNotification(notification.Name))
			}
		}
	}

	// Delete a vulnerability and verify the notification.
	if assert.Nil(t, vulnz.DeleteVulnerability(v1b.Namespace.Name, v1b.Name, datastore)) {
		notification, err = datastore.GetAvailableNotification(time.Second)
		assert.Nil(t, err)
		assert.NotEmpty(t, notification.Name)

		if assert.Nil(t, err) && assert.NotEmpty(t, notification.Name) {
			filledNotification, err := datastore.GetNotification(notification.Name)
			if assert.Nil(t, err) {
				assert.Nil(t, filledNotification.NewVulnerability)

				page := services.VulnerabilityNotificationFirstPage
				if assert.NotNil(t, filledNotification.OldVulnerability) {
					assert.Equal(t, v1b.Model, filledNotification.OldVulnerability.Model)
					vulnerability, err := vulnz.FindVulnerabilityByID(filledNotification.OldVulnerability.Model)
					if assert.Nil(t, err) {
						assert.Equal(t, v1b.Severity, vulnerability.Severity)
						page.OldVulnerability, err = layerz.LoadLayerIntroducingVulnerability(&vulnerability, 2, page.OldVulnerability)
						if assert.Nil(t, err) {
							assert.Len(t, vulnerability.LayersIntroducingVulnerability, 1)
						}
					}
				}
			}

			assert.Nil(t, datastore.DeleteNotification(notification.Name))
		}
	}
}
