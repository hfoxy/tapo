package tapo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"
)

type Tapo struct {
	ip           net.IP
	pk           *rsa.PrivateKey
	email        string
	password     string
	encryptedKey string
	handshakeAt  time.Time
	sessionId    string
	token        string
	key          []byte
	iv           []byte
	client       *http.Client
	terminalUUID string
}

func NewTapo(ip string, email string, password string) (*Tapo, error) {
	d := &Tapo{
		ip:     net.ParseIP(ip),
		client: http.DefaultClient,
	}
	pk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return d, err
	}
	d.pk = pk

	// set username base64 sha1
	h := sha1.New()
	h.Write([]byte(email))
	d.email = base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(h.Sum(nil))))
	// set password base64
	d.password = base64.StdEncoding.EncodeToString([]byte(password))
	// start session
	if err := d.Handshake(); err != nil {
		return d, err
	}
	// get token
	if err := d.Login(); err != nil {
		return d, err
	}
	return d, nil
}

func (d *Tapo) encrypt(p map[string]interface{}) string {
	in, _ := json.Marshal(p)

	block, err := aes.NewCipher(d.key)
	if err != nil {
		log.Fatalln(err)
	}

	// PKCS7 padding
	padding := block.BlockSize() - len(in)%block.BlockSize()
	in = append(in, bytes.Repeat([]byte{byte(padding)}, padding)...)
	out := make([]byte, len(in))
	mode := cipher.NewCBCEncrypter(block, d.iv)
	mode.CryptBlocks(out, in)
	s := base64.StdEncoding.EncodeToString(out) // + "\\" + "n"
	return s

}

func (d *Tapo) decrypt(in []byte) []byte {
	block, err := aes.NewCipher(d.key)
	if err != nil {
		log.Fatalln(err)
	}
	out := make([]byte, len(in))
	mode := cipher.NewCBCDecrypter(block, d.iv)
	mode.CryptBlocks(out, in)
	length := len(out)
	unpadding := int(out[length-1])
	out = out[:(length - unpadding)]
	return out
}

func (d *Tapo) ensureTerminalUUID() (string, error) {
	if d.terminalUUID != "" {
		return d.terminalUUID, nil
	}

	i, err := d.DeviceInfo()
	if err != nil {
		return "", err
	}
	d.terminalUUID = i["result"].(map[string]interface{})["mac"].(string)
	return d.terminalUUID, nil
}

func (d *Tapo) Handshake() error {
	u, err := url.Parse(fmt.Sprintf("http://%s/app", d.ip))
	if err != nil {
		return err
	}
	publicKeyDer, err := x509.MarshalPKIXPublicKey(d.pk.Public())
	if err != nil {
		return err
	}
	publicKeyBlock := pem.Block{Type: "PUBLIC KEY", Headers: nil, Bytes: publicKeyDer}
	publicKey := string(pem.EncodeToMemory(&publicKeyBlock))

	body, err := json.Marshal(map[string]interface{}{
		"method": "handshake",
		"params": map[string]interface{}{
			"key":             publicKey,
			"requestTimeMils": 0,
		},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", u.String(), bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header = map[string][]string{"Content-Type": {"application/json"}}
	req.Close = true
	res, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	var v map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return err
	}

	d.encryptedKey = v["result"].(map[string]interface{})["key"].(string)
	d.sessionId = res.Cookies()[0].String()
	d.handshakeAt = time.Now()

	// key 0-15, iv, 16-32
	sig, _ := base64.StdEncoding.DecodeString(d.encryptedKey)
	parts, err := rsa.DecryptPKCS1v15(nil, d.pk, sig)
	if err != nil {
		return err
	}
	d.key = parts[:16]
	d.iv = parts[16:]
	return nil
}

func (d *Tapo) RequestPath(path string, method string, body map[string]interface{}) (map[string]interface{}, error) {
	u, err := url.Parse(fmt.Sprintf("http://%s%s", d.ip, path))
	if err != nil {
		return nil, err
	}

	if d.token != "" {
		q := u.Query()
		q.Set("token", d.token)
		u.RawQuery = q.Encode()
	}

	return d.Request(u.String(), method, body)
}

func (d *Tapo) RequestResult(url string, method string, body map[string]interface{}, result any) error {
	b, err := d.RequestRaw(url, method, body)
	if err != nil {
		return err
	}

	err = json.Unmarshal(b, result)
	if err != nil {
		return err
	}

	return nil
}

func (d *Tapo) Request(url string, method string, body map[string]interface{}) (map[string]interface{}, error) {
	b, err := d.RequestRaw(url, method, body)
	if err != nil {
		return nil, err
	}

	var v map[string]interface{}
	err = json.Unmarshal(b, &v)
	if err != nil {
		return nil, err
	}

	return v, nil
}

func (d *Tapo) RequestRaw(url string, method string, body map[string]interface{}) ([]byte, error) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	if err := enc.Encode(body); err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(method, url, buf)
	req.Header.Set("Cookie", d.sessionId)
	req.Close = true

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("response status code %d", res.StatusCode)
	}

	var v map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return nil, err
	}

	encRes, err := base64.StdEncoding.DecodeString(v["result"].(map[string]interface{})["response"].(string))
	if err != nil {
		return nil, err
	}

	b := d.decrypt(encRes)
	return b, nil
}

func (d *Tapo) Login() error {
	res, err := d.Request(
		fmt.Sprintf("http://%s/app", d.ip),
		"POST",
		map[string]interface{}{
			"method": "securePassthrough",
			"params": map[string]interface{}{
				"request": d.encrypt(map[string]interface{}{
					"method": "login_device",
					"params": map[string]interface{}{
						"username": d.email,
						"password": d.password,
					},
				}),
			},
		},
	)
	if err != nil {
		return err
	}
	d.token = res["result"].(map[string]interface{})["token"].(string)
	return nil
}

func (d *Tapo) EnergyUsage() (map[string]interface{}, error) {
	terminalUUID, err := d.ensureTerminalUUID()
	if err != nil {
		return nil, err
	}
	return d.Request(
		fmt.Sprintf("http://%s/app?token=%s", d.ip, d.token),
		"POST",
		map[string]interface{}{
			"method": "securePassthrough",
			"params": map[string]interface{}{
				"request": d.encrypt(map[string]interface{}{
					"method":          "get_energy_usage",
					"requestTimeMils": time.Now().Unix(),
					"terminalUUID":    terminalUUID,
				}),
			},
		},
	)
}

var emptyEnergyUsage = EnergyUsage{}

func (d *Tapo) GetEnergyUsage() (EnergyUsage, error) {
	result := EnergyUsage{}
	terminalUUID, err := d.ensureTerminalUUID()
	if err != nil {
		return emptyEnergyUsage, err
	}

	err = d.RequestResult(
		fmt.Sprintf("http://%s/app?token=%s", d.ip, d.token),
		"POST",
		map[string]interface{}{
			"method": "securePassthrough",
			"params": map[string]interface{}{
				"request": d.encrypt(map[string]interface{}{
					"method":          "get_energy_usage",
					"requestTimeMils": time.Now().Unix(),
					"terminalUUID":    terminalUUID,
				}),
			},
		},
		&result,
	)

	return result, err
}

func (d *Tapo) DeviceInfo() (map[string]interface{}, error) {
	return d.Request(
		fmt.Sprintf("http://%s/app?token=%s", d.ip, d.token),
		"POST",
		map[string]interface{}{
			"method": "securePassthrough",
			"params": map[string]interface{}{
				"request": d.encrypt(
					map[string]interface{}{
						"method":          "get_device_info",
						"requestTimeMils": 0,
					},
				),
			},
		},
	)
}

var emptyDeviceInfo = DeviceInfo{}

func (d *Tapo) GetDeviceInfo() (DeviceInfo, error) {
	result := DeviceInfo{}
	err := d.RequestResult(
		fmt.Sprintf("http://%s/app?token=%s", d.ip, d.token),
		"POST",
		map[string]interface{}{
			"method": "securePassthrough",
			"params": map[string]interface{}{
				"request": d.encrypt(
					map[string]interface{}{
						"method":          "get_device_info",
						"requestTimeMils": 0,
					},
				),
			},
		},
		&result,
	)

	return emptyDeviceInfo, err
}

func (d *Tapo) DeviceRunningInfo() (map[string]interface{}, error) {
	return d.Request(
		fmt.Sprintf("http://%s/app?token=%s", d.ip, d.token),
		"POST",
		map[string]interface{}{
			"method": "securePassthrough",
			"params": map[string]interface{}{
				"request": d.encrypt(
					map[string]interface{}{
						"method":          "get_device_running_info",
						"requestTimeMils": 0,
					},
				),
			},
		},
	)
}

var emptyDeviceRunningInfo = DeviceRunningInfo{}

func (d *Tapo) GetDeviceRunningInfo() (DeviceRunningInfo, error) {
	result := DeviceRunningInfo{}
	err := d.RequestResult(
		fmt.Sprintf("http://%s/app?token=%s", d.ip, d.token),
		"POST",
		map[string]interface{}{
			"method": "securePassthrough",
			"params": map[string]interface{}{
				"request": d.encrypt(
					map[string]interface{}{
						"method":          "get_device_running_info",
						"requestTimeMils": 0,
					},
				),
			},
		},
		&result,
	)

	return emptyDeviceRunningInfo, err
}

func (d *Tapo) TurnOn() (map[string]interface{}, error) {
	terminalUUID, err := d.ensureTerminalUUID()
	if err != nil {
		return nil, err
	}
	return d.Request(
		fmt.Sprintf("http://%s/app?token=%s", d.ip, d.token),
		"POST",
		map[string]interface{}{
			"method": "securePassthrough",
			"params": map[string]interface{}{
				"request": d.encrypt(
					map[string]interface{}{
						"method": "set_device_info",
						"params": map[string]interface{}{
							"device_on": true,
						},
						"requestTimeMils": 0,
						"terminalUUID":    terminalUUID,
					},
				),
			},
		},
	)
}

func (d *Tapo) TurnOff() (map[string]interface{}, error) {
	terminalUUID, err := d.ensureTerminalUUID()
	if err != nil {
		return nil, err
	}
	return d.Request(
		fmt.Sprintf("http://%s/app?token=%s", d.ip, d.token),
		"POST",
		map[string]interface{}{
			"method": "securePassthrough",
			"params": map[string]interface{}{
				"request": d.encrypt(
					map[string]interface{}{
						"method": "set_device_info",
						"params": map[string]interface{}{
							"device_on": false,
						},
						"requestTimeMils": 0,
						"terminalUUID":    terminalUUID,
					},
				),
			},
		},
	)
}
