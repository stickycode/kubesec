package cmd

import (
	"github.com/shyiko/kubesec/gpg"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestMergeWithEncryptedTarget(t *testing.T) {
	if _, err := Merge(
		[]byte(`kind: Secret
data:
  ANOTHER_KEY: 1YCDl2ru+xjkRdSNQzJhYLssvaE=.qYp+dWMiZzSZ0q12.O8u3oaDqJIrMt9MXFKK8eA==
  KEY: AgsWlPl4J9U=.5pxxHJKYI/hnLkOe.swJPGDWdYL3ygKJQJJSpdg==
# kubesec:v:1
# kubesec:pgp:160A7A9CF46221A56B06AD64461A804F2609FD89:LS0tLS1CRUdJTiBQR1AgTUVTU0FHRS0tLS0tCgpoUUlNQTNVUG1uTmU3UFpBQVJBQXh2RS9PNnFHRURLY3ZCay9zdXllamI3SU9FdUZDNHY1OUFtbHQ0OFQzZW5iCmU2QktWellLZUUyaDVPRTdYUXY5VitSeGxnbm15dnh1OUdqU1B6WnJsTTdTaU9kL2JMS0Y0aTJsOGxQUFBoblUKRWFTbEQxY2ZITC9jYkZQMm0vUUtEdUQ4MG5BekgvOUEwd1JMS3FWYXBsMXFXSmNmWmxWbElKd0JBdk1PMXBOLwptNmJNMHpaOUFBYmJnZUlSdklKVjhhb0FzdHVPeDREQlZrdVJtRHRYZk9IZDJRV2RycTBMeVRjeVZvY2FEK3l3CkxSSEdqZ1U4L3ZMeURQYy9OV3htdE1YczNPM01rcEdNa1BGdk9nVllqV21uZnlVaW12aE0yWG5lSUJUOHNRVU8KL0hyOFpLeG1XZVpzNmZnRlZua2dpTkZRaWVheEVBNWwvMDBpQ2h1YzRLcGN5WWQ5a084cDVWb0FLSE5YcFVqTgpFczRFL2RoT2htUzVYZ2lNSUFtUUJhZWgrOU9tNmNKNnRoZ1BwMVk0enRpRnI3NWRETkIxaWRrNTFpS2tEdzBpCmVMT3BKTmtFTWxlby9SVmsyUk1ybDg2Q29CWlN2bDRRTmdaTVl1TGZQM210cmQxaHRMaVJ0ekFZaTNBREZrcHYKanZHdUJGdG5KekwzUVE5WXRDTjI0UE82cG05cE9DOTZwVUE0MU8zNHVsZEZkYUw2eXo3MkJ1NUg5WnNwbiswKwo2cXAvdXhZU2ltdEhNWldvYzhiWDRxVlRlZzR5SFZ3Yjh5OGdSVlcwWUZrRHhLcmZ2cXVZT01lTjZqU29ldUxwCmdRcnFUVUM3dVR5ZXdQaFNBZk9PcWladVVoT3JmT0lkTlpkSFhSOWRiWVhrOG1VMm1ZTkhsU1RTNmdMOHBzSFMKWndHMTJxZEt6TmxEZXN5cGpQekd0NldaVm0yOCtNNlhtY2hGQWdrclNPdkpCdG1Ia214bnZaY2hoU2FabXpKWQpFOFBjdlo0SitGbE9MU3I0eW1RWG4vSEF1M1NaVUt3dGo3bVZPWVpucVNBTjFaSk80V2IvOWNkdVo4NUl5K21FCm9WcUt3N2xmQW9vPQo9bXlpVwotLS0tLUVORCBQR1AgTUVTU0FHRS0tLS0tCg==
`),
		[]byte(`kind: Secret
data:
  YET_ANOTHER_KEY: wJ5nNssGFZHvCfabBAElcVTSHfkfPXSl.o2J2BXdkfoW+45Am.umGbbu1Hc5wfGUt2OhIOkQ==
  KEY: trb+MUYyWaw=.fkR7QgUBLp/y943i.8+/1ty5wFo3tLo3QLETiLA==
# kubesec:v:1
# kubesec:pgp:160A7A9CF46221A56B06AD64461A804F2609FD89:LS0tLS1CRUdJTiBQR1AgTUVTU0FHRS0tLS0tCgpoUUlNQTNVUG1uTmU3UFpBQVJBQXhtN2RVT0NMa2FucTNsbVZUTVhQY0lpcXFiUWh0dHJDZkN2SGY2emdiZ0FXCk1HNiswbUhuc0hza3pVK2c3Q1RrS1ZwY1djQklVOUs3c2NmMnZZN1RNRWRCMjM3eDdONG1ENXpDQXFpMCtWWVkKRVl1eDZBTnJRU1ZmYy81SUUyRFZrUkJiWUxXdUpLSDRRczA2UEtYakFxVkhpRTY0aFBpL29sc3YzT1F3V2UrdgpDV0h1MTVqODY5YkhkakszR3VWU2dXTm5OOURvVDhLSDdBR0hSN2hUb0YrVUhmcGdpTDRDNFdlZlVxN3NUVnN2Cm9EMzNpZkpxV1FUMi9ya2hERk1QcWJzeTBtcUU4d0I0NiszZ1lpOEJ5RnZqc2RwUVZDNEdoYkNXWS91aDlYbDcKSitsdnFCMXV2cTFnbE05eXV6L1BrN1QvWFZqY3d2VE0yNHQ0VGlwWlpRRHU3SW9JcXZmWU1RRlp3WWkyMVlrLwozTFlPdmlvT2FJNURtVjZRTXFZMllndm56QzAvTTRrZUFHVWRoNU12NkwwLzlQYmZWWmxMVlRWZ3JKSDg2cHlWCjVSWmVDbE8vVE80ZmJ2UWU0bjFrUnVUTVRFM01DWEYveE5kMWlTTjNmekNmMEg4SzZ2Z3Z3aFZsdWtRVGc5b08KdnBHWkE3dE5nRmQ3SklNZnJFOVJZL1h0QWQydGYxOEZLZTFvUVdRdFJmRGpTMjBWZU5GdkF5eStOTmpRZ0JScgprOE04bVRBck5QM1p1bUFzSXJrUHBLNnlOQ25lRXlCb24yNDk0NWlDaFZCTFpJS0pWcGVGeVhybFVyeUtMWC8vClZ4a1V3a0RMSHdldnYycXFiRWZkdlZxQXVqU3RnT0M0REcwOXUxbmpETW4zMFdJdWtpbGtXYU13WTNmS0RQTFMKWndHQUwxeXFOTVRybVJHZkFVeGU3d1RxVFFONGt0ZE9FZHhHNW81Y3hIVS9mNFliWlpQRWVaczdPSjJtZXdmRwpMWG5QSHo1SEpFTWE0K3BiR3REdlE4N2U0TURPSmhPL3NVQUp4cGlWdkNjeVN3T3ZVU2Y1akYvOGpkdUxJQ0d1Ck1aNEV0eVdWblFRPQo9SnNWeAotLS0tLUVORCBQR1AgTUVTU0FHRS0tLS0tCg==
`),
	); err == nil {
		t.Fail()
	} else {
		actual := err.Error()
		expected := "[target] must not be encrypted"
		if actual != expected {
			t.Fatalf("actual: %#v != expected: %#v", actual, expected)
		}
	}
}

func TestMergeWithUnencryptedSource(t *testing.T) {
	if _, err := Merge(
		[]byte(`kind: Secret
data:
  ANOTHER_KEY: ANOTHER_VALUE
  KEY: VALUE
`),
		[]byte(`kind: Secret
data:
  KEY: DEFAULT_VALUE
`),
	); err == nil {
		t.Fail()
	} else {
		actual := err.Error()
		expected := "[source] must be encrypted"
		if actual != expected {
			t.Fatalf("actual: %#v != expected: %#v", actual, expected)
		}
	}
}

func TestMerge(t *testing.T) {
	os.Setenv("HOME", "../")
	gpg.SetPassphrase("test")
	gpg.SetKeyring("test.keyring")

	encrypted, err := EncryptWithContext(
		[]byte(`{"kind":"Secret","data":{"KEY":"VkFMVUU=","ANOTHER_KEY":"QU5PVEhFUl9WQUxVRQ=="}}`),
		EncryptionContext{},
	)
	if err != nil {
		t.Fatal(err)
	}
	encryptedRS, err := unmarshal(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	encryptedValue := encryptedRS.data()["KEY"]
	actual, err := Merge(
		[]byte(encrypted),
		[]byte(`kind: Secret
data:
  YET_ANOTHER_KEY: REVGQVVMVF9ZRVRfQU5PVEhFUl9WQUxVRQ==
  KEY: REVGQVVMVF9WQUxVRQ==
`),
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := `data:
  KEY: ` + encryptedValue + `
  YET_ANOTHER_KEY: ANYTHING
kind: Secret
# kubesec:v:3
# kubesec:pgp:ANYTHING
# kubesec:mac:ANYTHING`
	if !regexp.MustCompile(strings.Replace(regexp.QuoteMeta(expected), "ANYTHING", "[^\\n]*", -1)).
		MatchString(string(actual)) {
		t.Fatalf("actual: %#v != expected: %#v", string(actual), expected)
	}
}
