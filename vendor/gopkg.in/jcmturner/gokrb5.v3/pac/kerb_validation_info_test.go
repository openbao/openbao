package pac

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/gokrb5.v3/mstypes"
	"gopkg.in/jcmturner/gokrb5.v3/testdata"
	"testing"
	"time"
)

func TestKerbValidationInfo_Unmarshal(t *testing.T) {
	b, err := hex.DecodeString(testdata.TestVectors["PAC_Kerb_Validation_Info_MS"])
	if err != nil {
		t.Fatal("Could not decode test data hex string")
	}
	var k KerbValidationInfo
	err = k.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling KerbValidationInfo: %v", err)
	}
	assert.Equal(t, time.Date(2006, 4, 28, 1, 42, 50, 925640100, time.UTC), k.LogOnTime.Time(), "LogOnTime not as expected")
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551516, time.UTC), k.LogOffTime.Time(), "LogOffTime not as expected")
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551516, time.UTC), k.KickOffTime.Time(), "KickOffTime not as expected")
	assert.Equal(t, time.Date(2006, 3, 18, 10, 44, 54, 837147900, time.UTC), k.PasswordLastSet.Time(), "PasswordLastSet not as expected")
	assert.Equal(t, time.Date(2006, 3, 19, 10, 44, 54, 837147900, time.UTC), k.PasswordCanChange.Time(), "PasswordCanChange not as expected")

	assert.Equal(t, "lzhu", k.EffectiveName.Value, "EffectiveName not as expected")
	assert.Equal(t, "Liqiang(Larry) Zhu", k.FullName.Value, "EffectiveName not as expected")
	assert.Equal(t, "ntds2.bat", k.LogonScript.Value, "EffectiveName not as expected")
	assert.Equal(t, "", k.ProfilePath.Value, "EffectiveName not as expected")
	assert.Equal(t, "", k.HomeDirectory.Value, "EffectiveName not as expected")
	assert.Equal(t, "", k.HomeDirectoryDrive.Value, "EffectiveName not as expected")
	assert.Equal(t, uint32(131088), k.ProfilePath.BufferPrt, "EffectiveName not as expected")
	assert.Equal(t, uint32(131092), k.HomeDirectory.BufferPrt, "EffectiveName not as expected")
	assert.Equal(t, uint32(131096), k.HomeDirectoryDrive.BufferPrt, "EffectiveName not as expected")

	assert.Equal(t, uint16(4180), k.LogonCount, "LogonCount not as expected")
	assert.Equal(t, uint16(0), k.BadPasswordCount, "BadPasswordCount not as expected")
	assert.Equal(t, uint32(2914711), k.UserID, "UserID not as expected")
	assert.Equal(t, uint32(513), k.PrimaryGroupID, "PrimaryGroupID not as expected")
	assert.Equal(t, uint32(26), k.GroupCount, "GroupCount not as expected")
	assert.Equal(t, uint32(131100), k.pGroupIDs, "pGroupIDs not as expected")

	gids := []mstypes.GroupMembership{
		{RelativeID: 3392609, Attributes: 7},
		{RelativeID: 2999049, Attributes: 7},
		{RelativeID: 3322974, Attributes: 7},
		{RelativeID: 513, Attributes: 7},
		{RelativeID: 2931095, Attributes: 7},
		{RelativeID: 3338539, Attributes: 7},
		{RelativeID: 3354830, Attributes: 7},
		{RelativeID: 3026599, Attributes: 7},
		{RelativeID: 3338538, Attributes: 7},
		{RelativeID: 2931096, Attributes: 7},
		{RelativeID: 3392610, Attributes: 7},
		{RelativeID: 3342740, Attributes: 7},
		{RelativeID: 3392630, Attributes: 7},
		{RelativeID: 3014318, Attributes: 7},
		{RelativeID: 2937394, Attributes: 7},
		{RelativeID: 3278870, Attributes: 7},
		{RelativeID: 3038018, Attributes: 7},
		{RelativeID: 3322975, Attributes: 7},
		{RelativeID: 3513546, Attributes: 7},
		{RelativeID: 2966661, Attributes: 7},
		{RelativeID: 3338434, Attributes: 7},
		{RelativeID: 3271401, Attributes: 7},
		{RelativeID: 3051245, Attributes: 7},
		{RelativeID: 3271606, Attributes: 7},
		{RelativeID: 3026603, Attributes: 7},
		{RelativeID: 3018354, Attributes: 7},
	}
	assert.Equal(t, gids, k.GroupIDs, "GroupIDs not as expected")

	assert.Equal(t, uint32(32), k.UserFlags, "UserFlags not as expected")

	assert.Equal(t, mstypes.UserSessionKey{Data: []mstypes.CypherBlock{{Data: make([]byte, 8, 8)}, {Data: make([]byte, 8, 8)}}}, k.UserSessionKey, "UserSessionKey not as expected")

	assert.Equal(t, "NTDEV-DC-05", k.LogonServer.Value, "LogonServer not as expected")
	assert.Equal(t, "NTDEV", k.LogonDomainName.Value, "LogonDomainName not as expected")

	assert.Equal(t, uint32(131112), k.pLogonDomainID, "pLogonDomainID not as expected")

	assert.Equal(t, "S-1-5-21-397955417-626881126-188441444", k.LogonDomainID.ToString(), "LogonDomainID not as expected")

	assert.Equal(t, uint32(16), k.UserAccountControl, "UserAccountControl not as expected")
	assert.Equal(t, uint32(0), k.SubAuthStatus, "SubAuthStatus not as expected")
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551616, time.UTC), k.LastSuccessfulILogon.Time(), "LastSuccessfulILogon not as expected")
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551616, time.UTC), k.LastFailedILogon.Time(), "LastSuccessfulILogon not as expected")
	assert.Equal(t, uint32(0), k.FailedILogonCount, "FailedILogonCount not as expected")

	assert.Equal(t, uint32(13), k.SIDCount, "SIDCount not as expected")
	assert.Equal(t, uint32(131116), k.pExtraSIDs, "SIDCount not as expected")
	assert.Equal(t, int(k.SIDCount), len(k.ExtraSIDs), "SIDCount and size of ExtraSIDs list are not the same")

	var es = []struct {
		sid  string
		attr uint32
	}{
		{"S-1-5-21-773533881-1816936887-355810188-513", uint32(7)},
		{"S-1-5-21-397955417-626881126-188441444-3101812", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3291368", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3291341", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3322973", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3479105", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3271400", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3283393", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3338537", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3038991", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3037999", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3248111", uint32(536870919)},
	}
	for i, s := range es {
		assert.Equal(t, s.sid, k.ExtraSIDs[i].SID.ToString(), "ExtraSID SID value not as epxected")
		assert.Equal(t, s.attr, k.ExtraSIDs[i].Attributes, "ExtraSID Attributes value not as epxected")
	}

	assert.Equal(t, uint32(0), k.pResourceGroupDomainSID, "pResourceGroupDomainSID not as expected")
	assert.Equal(t, uint8(0), k.ResourceGroupDomainSID.SubAuthorityCount, "ResourceGroupDomainSID not as expected")
	assert.Equal(t, uint32(0), k.pResourceGroupIDs, "pResourceGroupIDs not as expected")
	assert.Equal(t, 0, len(k.ResourceGroupIDs), "ResourceGroupIDs not as expected")

	b, err = hex.DecodeString(testdata.TestVectors["PAC_Kerb_Validation_Info"])
	if err != nil {
		t.Fatal("Could not decode test data hex string")
	}
	var k2 KerbValidationInfo
	err = k2.Unmarshal(b)
	if err != nil {
		t.Fatal("Could not unmarshal KerbValidationInfo")
	}

	assert.Equal(t, time.Date(2017, 5, 6, 15, 53, 11, 825766900, time.UTC), k2.LogOnTime.Time(), "LogOnTime not as expected")
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551516, time.UTC), k2.LogOffTime.Time(), "LogOffTime not as expected")
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551516, time.UTC), k2.KickOffTime.Time(), "KickOffTime not as expected")
	assert.Equal(t, time.Date(2017, 5, 6, 7, 23, 8, 968750000, time.UTC), k2.PasswordLastSet.Time(), "PasswordLastSet not as expected")
	assert.Equal(t, time.Date(2017, 5, 7, 7, 23, 8, 968750000, time.UTC), k2.PasswordCanChange.Time(), "PasswordCanChange not as expected")

	assert.Equal(t, "testuser1", k2.EffectiveName.Value, "EffectiveName not as expected")
	assert.Equal(t, "Test1 User1", k2.FullName.Value, "EffectiveName not as expected")
	assert.Equal(t, "", k2.LogonScript.Value, "EffectiveName not as expected")
	assert.Equal(t, "", k2.ProfilePath.Value, "EffectiveName not as expected")
	assert.Equal(t, "", k2.HomeDirectory.Value, "EffectiveName not as expected")
	assert.Equal(t, "", k2.HomeDirectoryDrive.Value, "EffectiveName not as expected")
	assert.Equal(t, uint32(131088), k2.ProfilePath.BufferPrt, "EffectiveName not as expected")
	assert.Equal(t, uint32(131092), k2.HomeDirectory.BufferPrt, "EffectiveName not as expected")
	assert.Equal(t, uint32(131096), k2.HomeDirectoryDrive.BufferPrt, "EffectiveName not as expected")

	assert.Equal(t, uint16(216), k2.LogonCount, "LogonCount not as expected")
	assert.Equal(t, uint16(0), k2.BadPasswordCount, "BadPasswordCount not as expected")
	assert.Equal(t, uint32(1105), k2.UserID, "UserID not as expected")
	assert.Equal(t, uint32(513), k2.PrimaryGroupID, "PrimaryGroupID not as expected")
	assert.Equal(t, uint32(5), k2.GroupCount, "GroupCount not as expected")
	assert.Equal(t, uint32(131100), k2.pGroupIDs, "pGroupIDs not as expected")

	gids = []mstypes.GroupMembership{
		{RelativeID: 513, Attributes: 7},
		{RelativeID: 1108, Attributes: 7},
		{RelativeID: 1109, Attributes: 7},
		{RelativeID: 1115, Attributes: 7},
		{RelativeID: 1116, Attributes: 7},
	}
	assert.Equal(t, gids, k2.GroupIDs, "GroupIDs not as expected")

	assert.Equal(t, uint32(32), k2.UserFlags, "UserFlags not as expected")

	assert.Equal(t, mstypes.UserSessionKey{Data: []mstypes.CypherBlock{{Data: make([]byte, 8, 8)}, {Data: make([]byte, 8, 8)}}}, k2.UserSessionKey, "UserSessionKey not as expected")

	assert.Equal(t, "ADDC", k2.LogonServer.Value, "LogonServer not as expected")
	assert.Equal(t, "TEST", k2.LogonDomainName.Value, "LogonDomainName not as expected")

	assert.Equal(t, uint32(131112), k2.pLogonDomainID, "pLogonDomainID not as expected")

	assert.Equal(t, "S-1-5-21-3167651404-3865080224-2280184895", k2.LogonDomainID.ToString(), "LogonDomainID not as expected")

	assert.Equal(t, uint32(528), k2.UserAccountControl, "UserAccountControl not as expected")
	assert.Equal(t, uint32(0), k2.SubAuthStatus, "SubAuthStatus not as expected")
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551616, time.UTC), k2.LastSuccessfulILogon.Time(), "LastSuccessfulILogon not as expected")
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551616, time.UTC), k2.LastFailedILogon.Time(), "LastSuccessfulILogon not as expected")
	assert.Equal(t, uint32(0), k2.FailedILogonCount, "FailedILogonCount not as expected")

	assert.Equal(t, uint32(2), k2.SIDCount, "SIDCount not as expected")
	assert.Equal(t, uint32(131116), k2.pExtraSIDs, "SIDCount not as expected")
	assert.Equal(t, int(k2.SIDCount), len(k2.ExtraSIDs), "SIDCount and size of ExtraSIDs list are not the same")

	var es2 = []struct {
		sid  string
		attr uint32
	}{
		{"S-1-5-21-3167651404-3865080224-2280184895-1114", uint32(536870919)},
		{"S-1-5-21-3167651404-3865080224-2280184895-1111", uint32(536870919)},
	}
	for i, s := range es2 {
		assert.Equal(t, s.sid, k2.ExtraSIDs[i].SID.ToString(), "ExtraSID SID value not as epxected")
		assert.Equal(t, s.attr, k2.ExtraSIDs[i].Attributes, "ExtraSID Attributes value not as epxected")
	}

	assert.Equal(t, uint32(0), k2.pResourceGroupDomainSID, "pResourceGroupDomainSID not as expected")
	assert.Equal(t, uint8(0), k2.ResourceGroupDomainSID.SubAuthorityCount, "ResourceGroupDomainSID not as expected")
	assert.Equal(t, uint32(0), k2.pResourceGroupIDs, "pResourceGroupIDs not as expected")
	assert.Equal(t, 0, len(k2.ResourceGroupIDs), "ResourceGroupIDs not as expected")
}

func TestKerbValidationInfo_Unmarshal_DomainTrust(t *testing.T) {
	b, err := hex.DecodeString(testdata.TestVectors["PAC_Kerb_Validation_Info_Trust"])
	if err != nil {
		t.Fatal("Could not decode test data hex string")
	}
	var k KerbValidationInfo
	err = k.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling KerbValidationInfo: %v", err)
	}
	assert.Equal(t, time.Date(2017, 10, 14, 12, 03, 41, 52409900, time.UTC), k.LogOnTime.Time(), "LogOnTime not as expected")
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551516, time.UTC), k.LogOffTime.Time(), "LogOffTime not as expected")
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551516, time.UTC), k.KickOffTime.Time(), "KickOffTime not as expected")
	assert.Equal(t, time.Date(2017, 10, 10, 20, 42, 56, 220282300, time.UTC), k.PasswordLastSet.Time(), "PasswordLastSet not as expected")
	assert.Equal(t, time.Date(2017, 10, 11, 20, 42, 56, 220282300, time.UTC), k.PasswordCanChange.Time(), "PasswordCanChange not as expected")

	assert.Equal(t, "testuser1", k.EffectiveName.Value, "EffectiveName not as expected")
	assert.Equal(t, "Test1 User1", k.FullName.Value, "EffectiveName not as expected")
	assert.Equal(t, "", k.LogonScript.Value, "EffectiveName not as expected")
	assert.Equal(t, "", k.ProfilePath.Value, "EffectiveName not as expected")
	assert.Equal(t, "", k.HomeDirectory.Value, "EffectiveName not as expected")
	assert.Equal(t, "", k.HomeDirectoryDrive.Value, "EffectiveName not as expected")
	assert.Equal(t, uint32(131088), k.ProfilePath.BufferPrt, "EffectiveName not as expected")
	assert.Equal(t, uint32(131092), k.HomeDirectory.BufferPrt, "EffectiveName not as expected")
	assert.Equal(t, uint32(131096), k.HomeDirectoryDrive.BufferPrt, "EffectiveName not as expected")

	assert.Equal(t, uint16(46), k.LogonCount, "LogonCount not as expected")
	assert.Equal(t, uint16(0), k.BadPasswordCount, "BadPasswordCount not as expected")
	assert.Equal(t, uint32(1106), k.UserID, "UserID not as expected")
	assert.Equal(t, uint32(513), k.PrimaryGroupID, "PrimaryGroupID not as expected")
	assert.Equal(t, uint32(3), k.GroupCount, "GroupCount not as expected")
	assert.Equal(t, uint32(131100), k.pGroupIDs, "pGroupIDs not as expected")

	gids := []mstypes.GroupMembership{
		{RelativeID: 1110, Attributes: 7},
		{RelativeID: 513, Attributes: 7},
		{RelativeID: 1109, Attributes: 7},
	}
	assert.Equal(t, gids, k.GroupIDs, "GroupIDs not as expected")

	assert.Equal(t, uint32(544), k.UserFlags, "UserFlags not as expected")

	assert.Equal(t, mstypes.UserSessionKey{Data: []mstypes.CypherBlock{{Data: make([]byte, 8, 8)}, {Data: make([]byte, 8, 8)}}}, k.UserSessionKey, "UserSessionKey not as expected")

	assert.Equal(t, "UDC", k.LogonServer.Value, "LogonServer not as expected")
	assert.Equal(t, "USER", k.LogonDomainName.Value, "LogonDomainName not as expected")

	assert.Equal(t, uint32(131112), k.pLogonDomainID, "pLogonDomainID not as expected")

	assert.Equal(t, "S-1-5-21-2284869408-3503417140-1141177250", k.LogonDomainID.ToString(), "LogonDomainID not as expected")

	assert.Equal(t, uint32(528), k.UserAccountControl, "UserAccountControl not as expected")
	assert.Equal(t, uint32(0), k.SubAuthStatus, "SubAuthStatus not as expected")
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551616, time.UTC), k.LastSuccessfulILogon.Time(), "LastSuccessfulILogon not as expected")
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551616, time.UTC), k.LastFailedILogon.Time(), "LastSuccessfulILogon not as expected")
	assert.Equal(t, uint32(0), k.FailedILogonCount, "FailedILogonCount not as expected")

	assert.Equal(t, uint32(1), k.SIDCount, "SIDCount not as expected")
	assert.Equal(t, uint32(131116), k.pExtraSIDs, "SIDCount not as expected")
	assert.Equal(t, int(k.SIDCount), len(k.ExtraSIDs), "SIDCount and size of ExtraSIDs list are not the same")

	var es = []struct {
		sid  string
		attr uint32
	}{
		{"S-1-18-1", uint32(7)},
	}
	for i, s := range es {
		assert.Equal(t, s.sid, k.ExtraSIDs[i].SID.ToString(), "ExtraSID SID value not as epxected")
		assert.Equal(t, s.attr, k.ExtraSIDs[i].Attributes, "ExtraSID Attributes value not as epxected")
	}

	assert.Equal(t, uint32(131124), k.pResourceGroupDomainSID, "pResourceGroupDomainSID not as expected")
	assert.Equal(t, uint8(4), k.ResourceGroupDomainSID.SubAuthorityCount, "ResourceGroupDomainSID not as expected")
	assert.Equal(t, "S-1-5-21-3062750306-1230139592-1973306805", k.ResourceGroupDomainSID.ToString(), "ResourceGroupDomainSID value not as expected")
	assert.Equal(t, uint32(131128), k.pResourceGroupIDs, "pResourceGroupIDs not as expected")
	assert.Equal(t, 2, len(k.ResourceGroupIDs), "ResourceGroupIDs not as expected")
	rgids := []mstypes.GroupMembership{
		{RelativeID: 1107, Attributes: 536870919},
		{RelativeID: 1108, Attributes: 536870919},
	}
	assert.Equal(t, rgids, k.ResourceGroupIDs, "ResourceGroupIDs not as expected")
	groupSids := []string{"S-1-5-21-2284869408-3503417140-1141177250-1110",
		"S-1-5-21-2284869408-3503417140-1141177250-513",
		"S-1-5-21-2284869408-3503417140-1141177250-1109",
		"S-1-18-1",
		"S-1-5-21-3062750306-1230139592-1973306805-1107",
		"S-1-5-21-3062750306-1230139592-1973306805-1108"}
	assert.Equal(t, groupSids, k.GetGroupMembershipSIDs(), "GroupMembershipSIDs not as expected")
}
