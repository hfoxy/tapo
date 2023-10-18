package tapo

type DeviceInfo struct {
	ErrorCode int              `json:"error_code"`
	Result    DeviceInfoResult `json:"result"`
}

type DeviceInfoState struct {
}

type DeviceInfoDefaultStates struct {
	State DeviceInfoState `json:"state"`
	Type  string          `json:"type"`
}

type DeviceInfoResult struct {
	AutoOffRemainTime     int                     `json:"auto_off_remain_time"`
	AutoOffStatus         string                  `json:"auto_off_status"`
	Avatar                string                  `json:"avatar"`
	DefaultStates         DeviceInfoDefaultStates `json:"default_states"`
	DeviceID              string                  `json:"device_id"`
	DeviceOn              bool                    `json:"device_on"`
	FwID                  string                  `json:"fw_id"`
	FwVer                 string                  `json:"fw_ver"`
	HasSetLocationInfo    bool                    `json:"has_set_location_info"`
	HwID                  string                  `json:"hw_id"`
	HwVer                 string                  `json:"hw_ver"`
	IP                    string                  `json:"ip"`
	Lang                  string                  `json:"lang"`
	Latitude              int                     `json:"latitude"`
	Longitude             int                     `json:"longitude"`
	Mac                   string                  `json:"mac"`
	Model                 string                  `json:"model"`
	Nickname              string                  `json:"nickname"`
	OemID                 string                  `json:"oem_id"`
	OnTime                int                     `json:"on_time"`
	Overheated            bool                    `json:"overheated"`
	PowerProtectionStatus string                  `json:"power_protection_status"`
	Region                string                  `json:"region"`
	Rssi                  int                     `json:"rssi"`
	SignalLevel           int                     `json:"signal_level"`
	Specs                 string                  `json:"specs"`
	Ssid                  string                  `json:"ssid"`
	TimeDiff              int                     `json:"time_diff"`
	Type                  string                  `json:"type"`
}

type DeviceRunningInfo struct {
	ErrorCode int                     `json:"error_code"`
	Result    DeviceRunningInfoResult `json:"result"`
}

type DeviceRunningInfoResult struct {
	AutoOffRemainTime     int                     `json:"auto_off_remain_time"`
	AutoOffStatus         string                  `json:"auto_off_status"`
	Avatar                string                  `json:"avatar"`
	DefaultStates         DeviceInfoDefaultStates `json:"default_states"`
	DeviceID              string                  `json:"device_id"`
	DeviceOn              bool                    `json:"device_on"`
	FwVer                 string                  `json:"fw_ver"`
	HasSetLocationInfo    bool                    `json:"has_set_location_info"`
	IP                    string                  `json:"ip"`
	Lang                  string                  `json:"lang"`
	Latitude              int                     `json:"latitude"`
	Longitude             int                     `json:"longitude"`
	Nickname              string                  `json:"nickname"`
	OnTime                int                     `json:"on_time"`
	Overheated            bool                    `json:"overheated"`
	PowerProtectionStatus string                  `json:"power_protection_status"`
	Region                string                  `json:"region"`
	Rssi                  int                     `json:"rssi"`
	SignalLevel           int                     `json:"signal_level"`
	Specs                 string                  `json:"specs"`
}

type EnergyUsage struct {
	ErrorCode int               `json:"error_code"`
	Result    EnergyUsageResult `json:"result"`
}

type EnergyUsageResult struct {
	CurrentPower      int    `json:"current_power"`
	ElectricityCharge []int  `json:"electricity_charge"`
	LocalTime         string `json:"local_time"`
	MonthEnergy       int    `json:"month_energy"`
	MonthRuntime      int    `json:"month_runtime"`
	TodayEnergy       int    `json:"today_energy"`
	TodayRuntime      int    `json:"today_runtime"`
}
