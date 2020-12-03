package deliveryservice

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/apache/trafficcontrol/lib/go-log"
	"github.com/apache/trafficcontrol/lib/go-tc"
	"github.com/apache/trafficcontrol/traffic_ops/traffic_ops_golang/api"
	"github.com/apache/trafficcontrol/traffic_ops/traffic_ops_golang/auth"
	"github.com/apache/trafficcontrol/traffic_ops/traffic_ops_golang/config"
	"github.com/apache/trafficcontrol/traffic_ops/traffic_ops_golang/riaksvc"
	"github.com/apache/trafficcontrol/traffic_ops/traffic_ops_golang/tenant"
	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/certificate"
	"github.com/go-acme/lego/lego"
	"github.com/go-acme/lego/registration"
	"github.com/jmoiron/sqlx"
	"net/http"
	"strconv"
)

func RenewAcmeCertificate(w http.ResponseWriter, r *http.Request) {
	inf, userErr, sysErr, errCode := api.NewInfo(r, []string{"xmlid"}, nil)
	if userErr != nil || sysErr != nil {
		api.HandleErr(w, r, inf.Tx.Tx, errCode, userErr, sysErr)
		return
	}
	defer inf.Close()
	if inf.Config.RiakEnabled == false {
		api.HandleErr(w, r, inf.Tx.Tx, http.StatusInternalServerError, userErr, errors.New("deliveryservice.DeleteSSLKeys: Riak is not configured"))
		return
	}
	xmlID := inf.Params["xmlid"]

	if userErr, sysErr, errCode := tenant.Check(inf.User, xmlID, inf.Tx.Tx); userErr != nil || sysErr != nil {
		api.HandleErr(w, r, inf.Tx.Tx, errCode, userErr, sysErr)
		return
	}

	ctx, _ := context.WithTimeout(r.Context(), LetsEncryptTimeout)

	err := renewAcmeCerts(inf.Config, xmlID, ctx, inf.User)
	if err != nil {
		api.HandleErr(w, r, inf.Tx.Tx, http.StatusInternalServerError, nil, err)
	}

}

func renewAcmeCerts(cfg *config.Config, dsName string, ctx context.Context, currentUser *auth.CurrentUser) error {
	db, err := api.GetDB(ctx)
	if err != nil {
		log.Errorf(dsName+": Error getting db: %s", err.Error())
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		log.Errorf(dsName+": Error getting tx: %s", err.Error())
		return err
	}

	userTx, err := db.Begin()
	if err != nil {
		log.Errorf(dsName+": Error getting userTx: %s", err.Error())
		return err
	}
	defer userTx.Commit()

	logTx, err := db.Begin()
	if err != nil {
		log.Errorf(dsName+": Error getting logTx: %s", err.Error())
		return err
	}
	defer logTx.Commit()

	dsID, certVersion, err := getDSIdAndVersionFromName(db, dsName)
	if err != nil {
		return errors.New("querying DS info: " + err.Error())
	}
	if dsID == nil || *dsID == 0 {
		return errors.New("DS id for " + dsName + " was nil or 0")
	}
	if certVersion == nil || *certVersion == 0 {
		return errors.New("certificate for " + dsName + " could not be renewed because version was nil or 0")
	}

	keyObj, ok, err := riaksvc.GetDeliveryServiceSSLKeysObjV15(dsName, strconv.Itoa(int(*certVersion)), tx, cfg.RiakAuthOptions, cfg.RiakPort)
	if err != nil {
		return errors.New("getting ssl keys for xmlId: " + dsName + " and version: " + strconv.Itoa(int(*certVersion)) + " :" + err.Error())
	}
	if !ok {
		return errors.New("no object found for the specified key with xmlId: " + dsName + " and version: " + strconv.Itoa(int(*certVersion)))
	}

	err = base64DecodeCertificate(&keyObj.Certificate)
	if err != nil {
		return errors.New("decoding cert for XMLID " + dsName + " : " + err.Error())
	}

	acmeAccount := getAcmeAccountConfig(cfg, keyObj.AuthType)
	if acmeAccount == nil {
		return errors.New("No acme account information in cdn.conf for " + keyObj.AuthType)
	}

	storedAcmeInfo, err := getStoredAcmeInfo(userTx, acmeAccount.UserEmail)
	if err != nil {
		log.Errorf(dsName+": Error finding stored ACME information: %s", err.Error())
		api.CreateChangeLogRawTx(api.ApiChange, "DS: "+dsName+", ID: "+strconv.Itoa(*dsID)+", ACTION: FAILED to add SSL keys with "+acmeAccount.AcmeProvider, currentUser, logTx)
		return err
	}

	myUser := MyUser{}
	foundPreviousAccount := false
	userPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Errorf(dsName+": Error generating private key: %s", err.Error())
		api.CreateChangeLogRawTx(api.ApiChange, "DS: "+dsName+", ID: "+strconv.Itoa(*dsID)+", ACTION: FAILED to add SSL keys with "+acmeAccount.AcmeProvider, currentUser, logTx)
		return err
	}

	if storedAcmeInfo == nil || acmeAccount.UserEmail == "" {
		myUser = MyUser{
			key:   userPrivateKey,
			Email: acmeAccount.UserEmail,
		}
	} else {
		foundPreviousAccount = true
		myUser = MyUser{
			key:   &storedAcmeInfo.PrivateKey,
			Email: storedAcmeInfo.Email,
			Registration: &registration.Resource{
				URI: storedAcmeInfo.URI,
			},
		}
	}

	config := lego.NewConfig(&myUser)
	config.CADirURL = acmeAccount.AcmeUrl
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		log.Errorf(dsName+": Error creating acme client: %s", err.Error())
		api.CreateChangeLogRawTx(api.ApiChange, "DS: "+dsName+", ID: "+strconv.Itoa(*dsID)+", ACTION: FAILED to add SSL keys with "+acmeAccount.AcmeProvider, currentUser, logTx)
		return err
	}

	if foundPreviousAccount {
		log.Debugf("Found existing account with %s", acmeAccount.AcmeProvider)
		reg, err := client.Registration.QueryRegistration()
		if err != nil {
			log.Errorf(dsName+": Error querying %s for existing account: %s", acmeAccount.AcmeProvider, err.Error())
			api.CreateChangeLogRawTx(api.ApiChange, "DS: "+dsName+", ID: "+strconv.Itoa(*dsID)+", ACTION: FAILED to add SSL keys with "+acmeAccount.AcmeProvider, currentUser, logTx)
			return err
		}
		myUser.Registration = reg
		if reg.Body.Status != "valid" {
			log.Debugf("Account found with %s is not valid.", acmeAccount.AcmeProvider)
			foundPreviousAccount = false
		}
	}
	if !foundPreviousAccount {
		reg, err := client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  acmeAccount.Kid,
			HmacEncoded:          acmeAccount.HmacEncoded,
		})
		if err != nil {
			log.Errorf(dsName+": Error registering acme client: %s", err.Error())
			api.CreateChangeLogRawTx(api.ApiChange, "DS: "+dsName+", ID: "+strconv.Itoa(*dsID)+", ACTION: FAILED to add SSL keys with "+acmeAccount.AcmeProvider, currentUser, logTx)
			return err
		}
		myUser.Registration = reg
		log.Debugf("Creating a new account with %s", acmeAccount.AcmeProvider)

		// save account info
		userKeyDer := x509.MarshalPKCS1PrivateKey(userPrivateKey)
		if userKeyDer == nil {
			log.Errorf("marshalling private key: nil der")
			api.CreateChangeLogRawTx(api.ApiChange, "DS: "+dsName+", ID: "+strconv.Itoa(*dsID)+", ACTION: FAILED to add SSL keys with "+acmeAccount.AcmeProvider, currentUser, logTx)
			return errors.New("marshalling private key: nil der")
		}
		userKeyBuf := bytes.Buffer{}
		if err := pem.Encode(&userKeyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: userKeyDer}); err != nil {
			log.Errorf("pem-encoding private key: " + err.Error())
			api.CreateChangeLogRawTx(api.ApiChange, "DS: "+dsName+", ID: "+strconv.Itoa(*dsID)+", ACTION: FAILED to add SSL keys with "+acmeAccount.AcmeProvider, currentUser, logTx)
			return errors.New("pem-encoding private key: " + err.Error())
		}
		userKeyPem := userKeyBuf.Bytes()
		err = storeAcmeAccountInfo(userTx, myUser.Email, string(userKeyPem), myUser.Registration.URI)
		if err != nil {
			log.Errorf("storing user account info: " + err.Error())
			api.CreateChangeLogRawTx(api.ApiChange, "DS: "+dsName+", ID: "+strconv.Itoa(*dsID)+", ACTION: FAILED to add SSL keys with "+acmeAccount.AcmeProvider, currentUser, logTx)
			return errors.New("storing user account info: " + err.Error())
		}
	}

	renewRequest := certificate.Resource{
		Certificate: []byte(keyObj.Certificate.Crt),
	}

	cert, err := client.Certificate.Renew(renewRequest, true, false)
	if err != nil {
		log.Errorf("Error obtaining acme certificate: %s", err.Error())
		return err
	}

	if validErr := ValidateCert([]byte(keyObj.Certificate.Crt), cert.Certificate); validErr != nil {
		log.Errorf("Certificate for ds %s failed validation: %s", dsName, validErr.Error())
		return errors.New(fmt.Sprintf("Certificate for ds %s failed validation: %s", dsName, validErr.Error()))
	}

	newCertObj := tc.DeliveryServiceSSLKeys{
		AuthType:        keyObj.AuthType,
		CDN:             keyObj.CDN,
		DeliveryService: keyObj.DeliveryService,
		Key:             keyObj.DeliveryService,
		Hostname:        keyObj.Hostname,
		Version:         keyObj.Version + 1,
	}

	newCertObj.Certificate = tc.DeliveryServiceSSLKeysCertificate{Crt: string(EncodePEMToLegacyPerlRiakFormat(cert.Certificate)), Key: string(EncodePEMToLegacyPerlRiakFormat(cert.PrivateKey)), CSR: string(EncodePEMToLegacyPerlRiakFormat([]byte(keyObj.Certificate.CSR)))}
	if err := riaksvc.PutDeliveryServiceSSLKeysObj(newCertObj, tx, cfg.RiakAuthOptions, cfg.RiakPort); err != nil {
		log.Errorf("Error posting acme certificate to riak: %s", err.Error())
		api.CreateChangeLogRawTx(api.ApiChange, "DS: "+dsName+", ID: "+strconv.Itoa(*dsID)+", ACTION: FAILED to add SSL keys with "+acmeAccount.AcmeProvider, currentUser, logTx)
		return errors.New(dsName + ": putting riak keys: " + err.Error())
	}

	tx2, err := db.Begin()
	if err != nil {
		log.Errorf("starting sql transaction for delivery service " + dsName + ": " + err.Error())
		return errors.New("starting sql transaction for delivery service " + dsName + ": " + err.Error())
	}

	if err := updateSSLKeyVersion(dsName, *certVersion+1, tx2); err != nil {
		log.Errorf("updating SSL key version for delivery service '" + dsName + "': " + err.Error())
		return errors.New("updating SSL key version for delivery service '" + dsName + "': " + err.Error())
	}
	tx2.Commit()

	return nil
}

func getAcmeAccountConfig(cfg *config.Config, acmeProvider string) *config.ConfigAcmeAccount {
	for _, acmeCfg := range cfg.AcmeAccounts {
		if acmeCfg.AcmeProvider == acmeProvider {
			return &acmeCfg
		}
	}
	return nil
}

func getDSIdAndVersionFromName(db *sqlx.DB, xmlId string) (*int, *int64, error) {
	var dsID int
	var certVersion int64

	if err := db.QueryRow(`SELECT id, ssl_key_version FROM deliveryservice WHERE xml_id = $1`, xmlId).Scan(&dsID, &certVersion); err != nil {
		return nil, nil, err
	}

	return &dsID, &certVersion, nil
}

func ValidateCert(oldCert []byte, newCert []byte) error {
	block, _ := pem.Decode(oldCert)
	if block == nil {
		return errors.New("Error decoding oldCert to parse expiration")
	}

	x509OldCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("Error parsing oldCert to get expiration - " + err.Error())
	}

	block, _ = pem.Decode(newCert)
	if block == nil {
		return errors.New("Error decoding newCert to parse expiration")
	}

	x509NewCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("Error parsing newCert to get expiration - " + err.Error())
	}

	// verify that the Common Name matches the old certificate
	if x509NewCert.Subject.CommonName != x509OldCert.Subject.CommonName {
		return errors.New(fmt.Sprintf("Common Names do not match. Previous: %s New: %s", x509OldCert.Subject.CommonName, x509NewCert.Subject.CommonName))
	}

	// verify that new expiration is after the old expiration
	if !x509NewCert.NotAfter.After(x509OldCert.NotAfter) {
		return errors.New(fmt.Sprintf("Expiration is not after the previous expiration. Expires: %v", x509NewCert.NotAfter))
	}

	return nil
}
