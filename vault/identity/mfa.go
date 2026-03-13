package identity

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/helper/identity"
	"github.com/openbao/openbao/helper/identity/mfa"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault/routing"
	otplib "github.com/pquerna/otp"
)

const (
	MfaMethodTypeTOTP         = "totp"
	MfaMethodTypeDuo          = "duo"
	MfaMethodTypeOkta         = "okta"
	MfaMethodTypePingID       = "pingid"
	MemDBLoginMFAConfigsTable = "login_mfa_configs"

	// defaultMaxTOTPValidateAttempts is the default value for the number
	// of failed attempts to validate a request subject to TOTP MFA. If the
	// number of failed totp passcode validations exceeds this max value, the
	// user needs to wait until a fresh totp passcode is generated.
	defaultMaxTOTPValidateAttempts = 5
)

func (i *IdentityStore) handleMFAMethodListTOTP(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleMFAMethodList(ctx, req, d, MfaMethodTypeTOTP)
}

func (i *IdentityStore) handleMFAMethodListDuo(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleMFAMethodList(ctx, req, d, MfaMethodTypeDuo)
}

func (i *IdentityStore) handleMFAMethodListOkta(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleMFAMethodList(ctx, req, d, MfaMethodTypeOkta)
}

func (i *IdentityStore) handleMFAMethodListPingID(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleMFAMethodList(ctx, req, d, MfaMethodTypePingID)
}

func (i *IdentityStore) handleMFAMethodListGlobal(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keys, configInfo, err := i.mfaBackend.MfaMethodList(ctx, "")
	if err != nil {
		return nil, err
	}

	return logical.ListResponseWithInfo(keys, configInfo), nil
}

func (i *IdentityStore) handleMFAMethodList(ctx context.Context, req *logical.Request, d *framework.FieldData, methodType string) (*logical.Response, error) {
	keys, configInfo, err := i.mfaBackend.MfaMethodList(ctx, methodType)
	if err != nil {
		return nil, err
	}

	return logical.ListResponseWithInfo(keys, configInfo), nil
}

func (i *IdentityStore) handleMFAMethodTOTPRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleMFAMethodReadCommon(ctx, req, d, MfaMethodTypeTOTP)
}

func (i *IdentityStore) handleMFAMethodOKTARead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleMFAMethodReadCommon(ctx, req, d, MfaMethodTypeOkta)
}

func (i *IdentityStore) handleMFAMethodDuoRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleMFAMethodReadCommon(ctx, req, d, MfaMethodTypeDuo)
}

func (i *IdentityStore) handleMFAMethodPingIDRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleMFAMethodReadCommon(ctx, req, d, MfaMethodTypePingID)
}

func (i *IdentityStore) handleMFAMethodReadGlobal(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleMFAMethodReadCommon(ctx, req, d, "")
}

func (i *IdentityStore) handleMFAMethodReadCommon(ctx context.Context, req *logical.Request, d *framework.FieldData, methodType string) (*logical.Response, error) {
	methodID := d.Get("method_id").(string)
	if methodID == "" {
		return logical.ErrorResponse("missing method ID"), nil
	}

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	respData, err := i.mfaBackend.MfaConfigReadByMethodID(methodID)
	if err != nil {
		return nil, err
	}

	if respData == nil {
		//nolint:nilnil
		return nil, nil
	}

	mfaNs, err := i.namespacer.NamespaceByID(ctx, respData["namespace_id"].(string))
	if err != nil {
		return nil, err
	}

	// reading the method config either from the same namespace or from the parent or from the child should all work
	if ns.ID != mfaNs.ID && !mfaNs.HasParent(ns) && !ns.HasParent(mfaNs) {
		return logical.ErrorResponse("request namespace does not match method namespace"), logical.ErrPermissionDenied
	}

	if methodType != "" && respData["type"] != methodType {
		return logical.ErrorResponse("failed to find the method ID under MFA type %s.", methodType), nil
	}

	return &logical.Response{
		Data: respData,
	}, nil
}

type MFABackend interface {
	Lock()
	Unlock()
	MemDBMFAConfigByID(string) (*mfa.Config, error)
	MemDBMFAConfigByName(context.Context, string) (*mfa.Config, error)
	PutMFAConfigByID(context.Context, *mfa.Config) error
	MemDBUpsertMFAConfig(context.Context, *mfa.Config) error
	MemDBMFALoginEnforcementConfigByNameAndNamespace(name, namespaceId string) (*mfa.MFAEnforcementConfig, error)
	MemDBUpsertMFALoginEnforcementConfig(ctx context.Context, eConfig *mfa.MFAEnforcementConfig) error
	MfaMethodList(ctx context.Context, s string) ([]string, map[string]any, error)
	MfaConfigReadByMethodID(methodID string) (map[string]any, error)
	DeleteMFAConfigByMethodID(context.Context, string, string, string) error
	HandleMFAGenerateTOTP(context.Context, *mfa.Config, string) (*logical.Response, error)
	MfaLoginEnforcementList(context.Context) ([]string, map[string]any, error)
	MfaLoginEnforcementConfigByNameAndNamespace(name, namespaceId string) (map[string]interface{}, error)
	ValidateAuthEntriesForAccessorOrType(ctx context.Context, ns *namespace.Namespace, validFunc func(entry *routing.MountEntry) bool) (bool, error)
	PutMFALoginEnforcementConfig(ctx context.Context, eConfig *mfa.MFAEnforcementConfig) error
	DeleteMFALoginEnforcementConfigByNameAndNamespace(ctx context.Context, name, namespaceId string) error
}

func (i *IdentityStore) handleMFAMethodUpdateCommon(ctx context.Context, req *logical.Request, d *framework.FieldData, methodType string) (*logical.Response, error) {
	var err error
	var mConfig *mfa.Config
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	methodID := d.Get("method_id").(string)
	methodName := d.Get("method_name").(string)

	b := i.mfaBackend
	b.Lock()
	defer b.Unlock()

	if methodID != "" {
		mConfig, err = b.MemDBMFAConfigByID(methodID)
		if err != nil {
			return nil, err
		}

		// If methodID is specified, but we didn't find anything, return a 404
		if mConfig == nil {
			//nolint:nilnil
			return nil, nil
		}
	}

	// check if an MFA method configuration exists with that method name
	if methodName != "" {
		namedMfaConfig, err := b.MemDBMFAConfigByName(ctx, methodName)
		if err != nil {
			return nil, err
		}
		if namedMfaConfig != nil {
			if mConfig == nil {
				mConfig = namedMfaConfig
			} else {
				if mConfig.ID != namedMfaConfig.ID {
					return nil, fmt.Errorf("a login MFA method configuration with the method name %s already exists", methodName)
				}
			}
		}
	}

	if mConfig == nil {
		configID, err := uuid.GenerateUUID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate an identifier for MFA config: %v", err)
		}
		mConfig = &mfa.Config{
			ID:          configID,
			Type:        methodType,
			NamespaceID: ns.ID,
		}
	}

	// Updating the method config name
	if methodName != "" {
		mConfig.Name = methodName
	}

	mfaNs, err := i.namespacer.NamespaceByID(ctx, mConfig.NamespaceID)
	if err != nil {
		return nil, err
	}

	// this logic assumes that the config namespace and the current
	// namespace should be the same. Note an ancestor of mfaNs is not allowed
	// to create/update methodID
	if ns.ID != mfaNs.ID {
		return logical.ErrorResponse("request namespace does not match method namespace"), nil
	}

	mConfig.Type = methodType
	usernameRaw, ok := d.GetOk("username_format")
	if ok {
		mConfig.UsernameFormat = usernameRaw.(string)
	}

	switch methodType {
	case MfaMethodTypeTOTP:
		err = parseTOTPConfig(mConfig, d)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

	case MfaMethodTypeOkta:
		err = parseOktaConfig(mConfig, d)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

	case MfaMethodTypeDuo:
		err = parseDuoConfig(mConfig, d)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

	case MfaMethodTypePingID:
		err = parsePingIDConfig(mConfig, d)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

	default:
		return logical.ErrorResponse("unrecognized type %q", methodType), nil
	}

	// Store the config
	err = b.PutMFAConfigByID(ctx, mConfig)
	if err != nil {
		return nil, err
	}

	// Back the config in MemDB
	err = b.MemDBUpsertMFAConfig(ctx, mConfig)
	if err != nil {
		return nil, err
	}

	if methodID == "" {
		return &logical.Response{
			Data: map[string]interface{}{
				"method_id": mConfig.ID,
			},
		}, nil
	} else {
		//nolint:nilnil
		return nil, nil
	}
}

func (i *IdentityStore) handleMFAMethodTOTPUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleMFAMethodUpdateCommon(ctx, req, d, MfaMethodTypeTOTP)
}

func (i *IdentityStore) handleMFAMethodOKTAUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleMFAMethodUpdateCommon(ctx, req, d, MfaMethodTypeOkta)
}

func (i *IdentityStore) handleMFAMethodDuoUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleMFAMethodUpdateCommon(ctx, req, d, MfaMethodTypeDuo)
}

func (i *IdentityStore) handleMFAMethodPingIDUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleMFAMethodUpdateCommon(ctx, req, d, MfaMethodTypePingID)
}

func (i *IdentityStore) handleMFAMethodTOTPDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleMFAMethodDeleteCommon(ctx, req, d, MfaMethodTypeTOTP)
}

func (i *IdentityStore) handleMFAMethodOKTADelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleMFAMethodDeleteCommon(ctx, req, d, MfaMethodTypeOkta)
}

func (i *IdentityStore) handleMFAMethodDUODelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleMFAMethodDeleteCommon(ctx, req, d, MfaMethodTypeDuo)
}

func (i *IdentityStore) handleMFAMethodPingIDDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleMFAMethodDeleteCommon(ctx, req, d, MfaMethodTypePingID)
}

func (i *IdentityStore) handleMFAMethodDeleteCommon(ctx context.Context, req *logical.Request, d *framework.FieldData, methodType string) (*logical.Response, error) {
	methodID := d.Get("method_id").(string)
	if methodID == "" {
		return logical.ErrorResponse("missing method ID"), nil
	}
	return nil, i.mfaBackend.DeleteMFAConfigByMethodID(ctx, methodID, methodType, MemDBLoginMFAConfigsTable)
}

func (i *IdentityStore) handleLoginMFAGenerateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleLoginMFAGenerateCommon(ctx, req, d.Get("method_id").(string), req.EntityID)
}

func (i *IdentityStore) handleLoginMFAAdminGenerateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return i.handleLoginMFAGenerateCommon(ctx, req, d.Get("method_id").(string), d.Get("entity_id").(string))
}

func (i *IdentityStore) handleLoginMFAGenerateCommon(ctx context.Context, req *logical.Request, methodID, entityID string) (*logical.Response, error) {
	if methodID == "" {
		return logical.ErrorResponse("missing method ID"), nil
	}

	if entityID == "" {
		return logical.ErrorResponse("missing entityID"), nil
	}

	mConfig, err := i.mfaBackend.MemDBMFAConfigByID(methodID)
	if err != nil {
		return nil, err
	}
	if mConfig == nil {
		return logical.ErrorResponse("configuration for method ID %q does not exist", methodID), nil
	}
	if mConfig.ID == "" {
		return nil, fmt.Errorf("configuration for method ID %q does not contain an identifier", methodID)
	}

	entity, err := i.MemDBEntityByID(ctx, entityID, true)
	if err != nil {
		return nil, fmt.Errorf("failed to find entity with ID %q: error: %w", entityID, err)
	}

	if entity == nil {
		return logical.ErrorResponse("invalid entity ID"), nil
	}

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return logical.ErrorResponse("failed to retrieve the namespace"), nil
	}
	if ns.ID != entity.NamespaceID {
		return logical.ErrorResponse("entity namespace ID does not match the current namespace ID"), nil
	}

	entityNS, err := i.namespacer.NamespaceByID(ctx, entity.NamespaceID)
	if err != nil {
		return logical.ErrorResponse("entity namespace not found"), nil
	}

	configNS, err := i.namespacer.NamespaceByID(ctx, mConfig.NamespaceID)
	if err != nil {
		return logical.ErrorResponse("methodID namespace not found"), nil
	}

	if configNS.ID != entityNS.ID && !entityNS.HasParent(configNS) {
		return logical.ErrorResponse("entity namespace %s outside of the config namespace %s", entityNS.Path, configNS.Path), nil
	}

	switch mConfig.Type {
	case MfaMethodTypeTOTP:
		return i.mfaBackend.HandleMFAGenerateTOTP(ctx, mConfig, entityID)
	default:
		return logical.ErrorResponse("generate not available for MFA type %q", mConfig.Type), nil
	}
}

// handleLoginMFAAdminDestroyUpdate does not remove the totp secret key from the storage
func (i *IdentityStore) handleLoginMFAAdminDestroyUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var entity *identity.Entity
	var err error

	methodID := d.Get("method_id").(string)
	if methodID == "" {
		return logical.ErrorResponse("missing method ID"), nil
	}

	entityID := d.Get("entity_id").(string)
	if entityID == "" {
		return logical.ErrorResponse("missing entity ID"), nil
	}

	entity, err = i.MemDBEntityByID(ctx, entityID, true)
	if err != nil {
		return nil, fmt.Errorf("failed to find entity with ID %q: error: %w", entityID, err)
	}

	if entity == nil {
		return logical.ErrorResponse("invalid entity ID"), nil
	}

	mConfig, err := i.mfaBackend.MemDBMFAConfigByID(methodID)
	if err != nil {
		return nil, err
	}

	if mConfig == nil {
		return logical.ErrorResponse("configuration for method ID %q does not exist", methodID), nil
	}

	if mConfig.ID == "" {
		return nil, fmt.Errorf("configuration for method ID %q does not contain an identifier", methodID)
	}

	if mConfig.Type != MfaMethodTypeTOTP {
		return nil, errors.New("method ID does not match TOTP type")
	}

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return logical.ErrorResponse("failed to retrieve the namespace"), nil
	}
	if ns.ID != entity.NamespaceID {
		return logical.ErrorResponse("entity namespace ID does not match the current namespace ID"), nil
	}

	entityNS, err := i.namespacer.NamespaceByID(ctx, entity.NamespaceID)
	if err != nil {
		return logical.ErrorResponse("entity namespace not found"), nil
	}

	configNS, err := i.namespacer.NamespaceByID(ctx, mConfig.NamespaceID)
	if err != nil {
		return logical.ErrorResponse("methodID namespace not found"), nil
	}

	if configNS.ID != entityNS.ID && !entityNS.HasParent(configNS) {
		return logical.ErrorResponse("entity namespace %s outside of the current namespace %s", entityNS.Path, ns.Path), nil
	}

	// destroying the secret on the entity
	if entity.MFASecrets != nil {
		delete(entity.MFASecrets, mConfig.ID)
	}

	err = i.UpsertEntity(ctx, entity, nil, true)
	if err != nil {
		return nil, fmt.Errorf("failed to persist MFA secret in entity, error: %w", err)
	}

	//nolint:nilnil
	return nil, nil
}

func (i *IdentityStore) handleMFALoginEnforcementList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keys, configInfo, err := i.mfaBackend.MfaLoginEnforcementList(ctx)
	if err != nil {
		return nil, err
	}

	return logical.ListResponseWithInfo(keys, configInfo), nil
}

func (i *IdentityStore) handleMFALoginEnforcementRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	respData, err := i.mfaBackend.MfaLoginEnforcementConfigByNameAndNamespace(name, ns.ID)
	if err != nil {
		return nil, err
	}

	if respData == nil {
		//nolint:nilnil
		return nil, nil
	}

	// The config is readable only from the same namespace
	if ns.ID != respData["namespace_id"].(string) {
		return logical.ErrorResponse("request namespace does not match method namespace"), nil
	}

	return &logical.Response{
		Data: respData,
	}, nil
}

func (i *IdentityStore) handleMFALoginEnforcementUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var err error
	var eConfig *mfa.MFAEnforcementConfig

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing enforcement name"), nil
	}

	b := i.mfaBackend
	b.Lock()
	defer b.Unlock()

	eConfig, err = b.MemDBMFALoginEnforcementConfigByNameAndNamespace(name, ns.ID)
	if err != nil {
		return nil, err
	}

	if eConfig == nil {
		configID, err := uuid.GenerateUUID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate an identifier for MFA login enforcement config: %w", err)
		}
		eConfig = &mfa.MFAEnforcementConfig{
			Name:        name,
			NamespaceID: ns.ID,
			ID:          configID,
		}
	}

	mfaMethodIds, ok := d.GetOk("mfa_method_ids")
	if !ok {
		return logical.ErrorResponse("missing method ids"), nil
	}

	for _, mmid := range mfaMethodIds.([]string) {
		// make sure this method id actually exists
		config, err := b.MfaConfigReadByMethodID(mmid)
		if err != nil {
			return nil, err
		}
		if config == nil {
			return logical.ErrorResponse("one of the provided method ids doesn't exist"), nil
		}

		mfaNs, err := i.namespacer.NamespaceByID(ctx, config["namespace_id"].(string))
		if err != nil {
			return logical.ErrorResponse("failed to retrieve config namespace"), nil
		}

		if ns.ID != mfaNs.ID && !ns.HasParent(mfaNs) {
			return logical.ErrorResponse("one of the provided method ids is in an incompatible namespace and can't be used"), nil
		}
	}
	eConfig.MFAMethodIDs = mfaMethodIds.([]string)

	oneOfLastFour := false
	authMethodAccessors, ok := d.GetOk("auth_method_accessors")
	if ok {
		for _, accessor := range authMethodAccessors.([]string) {
			found, err := b.ValidateAuthEntriesForAccessorOrType(ctx, ns, func(entry *routing.MountEntry) bool {
				return accessor == entry.Accessor
			})
			if err != nil {
				return nil, err
			}
			if !found {
				return logical.ErrorResponse("one of the auth method accessors provided is invalid"), nil
			}
		}
		eConfig.AuthMethodAccessors = authMethodAccessors.([]string)
		oneOfLastFour = true
	}

	authMethodTypes, ok := d.GetOk("auth_method_types")
	if ok {
		for _, authType := range authMethodTypes.([]string) {
			found, err := b.ValidateAuthEntriesForAccessorOrType(ctx, ns, func(entry *routing.MountEntry) bool {
				return authType == entry.Type
			})
			if err != nil {
				return nil, err
			}
			if !found {
				return logical.ErrorResponse("one of the auth method types provided is invalid"), nil
			}
		}
		eConfig.AuthMethodTypes = authMethodTypes.([]string)
		oneOfLastFour = true
	}

	identityGroupIds, ok := d.GetOk("identity_group_ids")
	if ok {
		for _, groupId := range identityGroupIds.([]string) {
			group, err := i.MemDBGroupByID(ctx, groupId, true)
			if err != nil {
				return nil, err
			}
			if group == nil {
				return logical.ErrorResponse("one of the provided group ids doesn't exist"), nil
			}
		}
		eConfig.IdentityGroupIds = identityGroupIds.([]string)
		oneOfLastFour = true
	}

	identityEntityIds, ok := d.GetOk("identity_entity_ids")
	if ok {
		for _, entityId := range identityEntityIds.([]string) {
			entity, err := i.MemDBEntityByID(ctx, entityId, true)
			if err != nil {
				return nil, err
			}
			if entity == nil {
				return logical.ErrorResponse("one of the provided entity ids doesn't exist"), nil
			}
		}
		eConfig.IdentityEntityIDs = identityEntityIds.([]string)
		oneOfLastFour = true
	}

	if !oneOfLastFour {
		return logical.ErrorResponse("One of auth_method_accessors, auth_method_types, identity_group_ids, identity_entity_ids must be specified"), nil
	}

	// Store the config
	err = b.PutMFALoginEnforcementConfig(ctx, eConfig)
	if err != nil {
		return nil, err
	}

	// Back the config in MemDB
	return nil, b.MemDBUpsertMFALoginEnforcementConfig(ctx, eConfig)
}

func (i *IdentityStore) handleMFALoginEnforcementDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	return nil, i.mfaBackend.DeleteMFALoginEnforcementConfigByNameAndNamespace(ctx, name, ns.ID)
}

func parseTOTPConfig(mConfig *mfa.Config, d *framework.FieldData) error {
	if mConfig == nil {
		return errors.New("config is nil")
	}

	if d == nil {
		return errors.New("field data is nil")
	}

	algorithm := d.Get("algorithm").(string)
	var keyAlgorithm otplib.Algorithm
	switch algorithm {
	case "SHA1":
		keyAlgorithm = otplib.AlgorithmSHA1
	case "SHA256":
		keyAlgorithm = otplib.AlgorithmSHA256
	case "SHA512":
		keyAlgorithm = otplib.AlgorithmSHA512
	default:
		return errors.New("unrecognized algorithm")
	}

	digits := d.Get("digits").(int)
	var keyDigits otplib.Digits
	switch digits {
	case 6:
		keyDigits = otplib.DigitsSix
	case 8:
		keyDigits = otplib.DigitsEight
	default:
		return errors.New("digits can only be 6 or 8")
	}

	period := d.Get("period").(int)
	if period <= 0 {
		return errors.New("period must be greater than zero")
	}

	skew := d.Get("skew").(int)
	switch skew {
	case 0:
	case 1:
	default:
		return errors.New("skew must be 0 or 1")
	}

	keySize := d.Get("key_size").(int)
	if keySize <= 0 {
		return errors.New("key_size must be greater than zero")
	}

	issuer := d.Get("issuer").(string)
	if issuer == "" {
		return errors.New("issuer must be set")
	}

	maxValidationAttempt := d.Get("max_validation_attempts").(int)
	if maxValidationAttempt < 0 {
		return errors.New("max_validation_attempts must be greater than zero")
	}
	if maxValidationAttempt == 0 {
		maxValidationAttempt = defaultMaxTOTPValidateAttempts
	}

	config := &mfa.TOTPConfig{
		Issuer:                issuer,
		Period:                uint32(period),
		Algorithm:             int32(keyAlgorithm),
		Digits:                int32(keyDigits),
		Skew:                  uint32(skew),
		KeySize:               uint32(keySize),
		QRSize:                int32(d.Get("qr_size").(int)),
		MaxValidationAttempts: uint32(maxValidationAttempt),
	}
	mConfig.Config = &mfa.Config_TOTPConfig{
		TOTPConfig: config,
	}

	return nil
}

func parseOktaConfig(mConfig *mfa.Config, d *framework.FieldData) error {
	if mConfig == nil {
		return errors.New("config is nil")
	}

	if d == nil {
		return errors.New("field data is nil")
	}

	oktaConfig := &mfa.OktaConfig{}

	orgName := d.Get("org_name").(string)
	if orgName == "" {
		return errors.New("org_name must be set")
	}
	oktaConfig.OrgName = orgName

	token := d.Get("api_token").(string)
	if token == "" {
		return errors.New("api_token must be set")
	}
	oktaConfig.APIToken = token

	productionRaw, productionOk := d.GetOk("production")
	if productionOk {
		oktaConfig.Production = productionRaw.(bool)
	} else {
		oktaConfig.Production = true
	}

	baseURLRaw, ok := d.GetOk("base_url")
	if ok {
		oktaConfig.BaseURL = baseURLRaw.(string)
	} else {
		// Only set if not using legacy production flag
		if !productionOk {
			oktaConfig.BaseURL = "okta.com"
		}
	}

	primaryEmailOnly := d.Get("primary_email").(bool)
	if primaryEmailOnly {
		oktaConfig.PrimaryEmail = true
	}

	_, err := url.Parse(fmt.Sprintf("https://%s,%s", oktaConfig.OrgName, oktaConfig.BaseURL))
	if err != nil {
		return fmt.Errorf("error parsing given base_url: %w", err)
	}

	mConfig.Config = &mfa.Config_OktaConfig{
		OktaConfig: oktaConfig,
	}

	return nil
}

func parseDuoConfig(mConfig *mfa.Config, d *framework.FieldData) error {
	secretKey := d.Get("secret_key").(string)
	if secretKey == "" {
		return errors.New("secret_key is empty")
	}

	integrationKey := d.Get("integration_key").(string)
	if integrationKey == "" {
		return errors.New("integration_key is empty")
	}

	apiHostname := d.Get("api_hostname").(string)
	if apiHostname == "" {
		return errors.New("api_hostname is empty")
	}

	config := &mfa.DuoConfig{
		SecretKey:      secretKey,
		IntegrationKey: integrationKey,
		APIHostname:    apiHostname,
		PushInfo:       d.Get("push_info").(string),
		UsePasscode:    d.Get("use_passcode").(bool),
	}

	mConfig.Config = &mfa.Config_DuoConfig{
		DuoConfig: config,
	}

	return nil
}

func parsePingIDConfig(mConfig *mfa.Config, d *framework.FieldData) error {
	fileString := d.Get("settings_file_base64").(string)
	if fileString == "" {
		return errors.New("settings_file_base64 is empty")
	}

	fileBytes, err := base64.StdEncoding.DecodeString(fileString)
	if err != nil {
		return err
	}

	config := &mfa.PingIDConfig{}
	for _, line := range strings.Split(string(fileBytes), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		splitLine := strings.SplitN(line, "=", 2)
		if len(splitLine) != 2 {
			return fmt.Errorf("pingid settings file contains a non-empty non-comment line that is not in key=value format: %q", line)
		}
		switch splitLine[0] {
		case "use_base64_key":
			config.UseBase64Key = splitLine[1]
		case "use_signature":
			result, err := parseutil.ParseBool(splitLine[1])
			if err != nil {
				return errors.New("error parsing use_signature value in pingid settings file")
			}
			config.UseSignature = result
		case "token":
			config.Token = splitLine[1]
		case "idp_url":
			config.IDPURL = splitLine[1]
		case "org_alias":
			config.OrgAlias = splitLine[1]
		case "admin_url":
			config.AdminURL = splitLine[1]
		case "authenticator_url":
			config.AuthenticatorURL = splitLine[1]
		default:
			return fmt.Errorf("unknown key %q in pingid settings file", splitLine[0])
		}
	}

	mConfig.Config = &mfa.Config_PingIDConfig{
		PingIDConfig: config,
	}

	return nil
}
