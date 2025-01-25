//go:build hsm && linux

package configutil

import (
	"context"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	p11 "github.com/openbao/go-kms-wrapping/wrappers/pkcs11/v2"
)

func GetPKCS11KMSFunc(kms *KMS, opts ...wrapping.Option) (wrapping.Wrapper, map[string]string, error) {
	wrapper := p11.NewWrapper()
	wrapperInfo, err := wrapper.SetConfig(context.Background(), append(opts, wrapping.WithConfigMap(kms.Config))...)
	if err != nil {
		return nil, nil, err
	}

	info := make(map[string]string)
	if wrapperInfo != nil {
		info["PKCS#11 KMS Library"] = wrapperInfo.Metadata["lib"]
		info["PKCS#11 KMS Key Label"] = wrapperInfo.Metadata["key_label"]
		info["PKCS#11 KMS Key ID"] = wrapperInfo.Metadata["key_id"]
		if val, present := wrapperInfo.Metadata["slot"]; present {
			info["PKCS#11 KMS Slot"] = val
		}
		if val, present := wrapperInfo.Metadata["token_label"]; present {
			info["PKCS#11 KMS Token Label"] = val
		}
		if val, present := wrapperInfo.Metadata["mechanism"]; present {
			info["PKCS#11 KMS Mechanism"] = val
		}
	}
	return wrapper, info, nil
}
