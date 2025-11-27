package main

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/gin-gonic/gin"
)

// 嵌入PDF文件
//
//go:embed HTTP推送接口说明.pdf
var pdfFile embed.FS

// 工具函数
func formatTimeForFileName(timeStr string) string {
	return strings.ReplaceAll(strings.ReplaceAll(timeStr, ":", "_"), " ", "_")
}

// 清理目录中超过指定数量的最老文件
func cleanupOldFiles(dirPath string, maxFiles int) error {
	// 确保目录存在
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		return nil
	}

	// 读取目录内容
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("读取目录失败: %v", err)
	}

	// 过滤出文件（排除子目录）并按修改时间排序
	var fileInfos []os.FileInfo
	for _, file := range files {
		if !file.IsDir() {
			info, err := file.Info()
			if err != nil {
				continue
			}
			fileInfos = append(fileInfos, info)
		}
	}

	// 如果文件数量不超过限制，直接返回
	if len(fileInfos) <= maxFiles {
		return nil
	}

	// 按修改时间升序排序（最老的文件在前）
	sort.Slice(fileInfos, func(i, j int) bool {
		return fileInfos[i].ModTime().Before(fileInfos[j].ModTime())
	})

	// 删除多余的最老文件
	filesToDelete := fileInfos[:len(fileInfos)-maxFiles]
	for _, fileInfo := range filesToDelete {
		filePath := filepath.Join(dirPath, fileInfo.Name())
		if err := os.Remove(filePath); err != nil {
			logError(fmt.Sprintf("删除文件失败: %s", filePath), err)
			continue
		}
		logInfo(fmt.Sprintf("已删除最老的文件: %s", filePath))
	}

	return nil
}

// 用于处理字符串类型的status参数
func getStatusStringString(status string) string {
	switch status {
	case "0":
		return "stop"
	case "1":
		return "start"
	case "2":
		return "pulse"
	default:
		return status
	}
}

// 用于处理整数类型的status参数
func getStatusStringInt(status int) string {
	switch status {
	case 0:
		return "stop"
	case 1:
		return "start"
	case 2:
		return "pulse"
	default:
		return fmt.Sprintf("%d", status)
	}
}

// min函数返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// 统一日志记录
func logError(context string, err error) {
	if err != nil {
		log.Printf("[ERROR] %s: %v", context, err)
	}
}

func logInfo(format string, args ...interface{}) {
	log.Printf("[INFO] "+format, args...)
}

func logDebug(format string, args ...interface{}) {
	log.Printf("[DEBUG] "+format, args...)
}

// 数据透传函数 - 使用完整URL地址透传
func forwardData(data []byte, path string) {
	if forwardURL == "" {
		return // 未设置透传地址，不执行透传
	}

	// 构建完整的透传URL，包含请求路径
	fullURL := forwardURL
	if path != "" && path != "/" {
		// 如果URL已经以/结尾，直接拼接路径
		if strings.HasSuffix(fullURL, "/") {
			fullURL += path[1:] // 去掉路径开头的/，避免双斜杠
		} else {
			fullURL += path
		}
	}

	// 使用HTTP客户端发送POST请求
	client := &http.Client{}

	// 创建请求
	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(data))
	if err != nil {
		logError(fmt.Sprintf("创建透传请求失败，URL: %s", fullURL), err)
		return
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		logError(fmt.Sprintf("透传数据失败，URL: %s", fullURL), err)
		return
	}
	defer resp.Body.Close()

	// 读取响应（可选）
	_, _ = io.Copy(io.Discard, resp.Body)

	logInfo("数据已透传到 %s，响应状态: %s", fullURL, resp.Status)
}

// 数据透传函数 - 包含请求路径
func forwardDataWithPath(data []byte, path string, ip, port string) {
	if ip == "" || port == "" {
		return // 未设置透传地址，不执行透传
	}

	// 创建TCP连接
	addr := fmt.Sprintf("%s:%s", ip, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		logError(fmt.Sprintf("透传数据失败，无法连接到 %s", addr), err)
		return
	}
	defer conn.Close()

	// 构建完整的透传数据，包含请求路径和原始数据
	// 格式: PATH: [path]\n[原始数据]
	fullData := fmt.Sprintf("PATH: %s\n%s", path, string(data))

	// 发送数据
	if _, err := conn.Write([]byte(fullData)); err != nil {
		logError(fmt.Sprintf("透传数据失败，发送到 %s", addr), err)
		return
	}

	logInfo("数据已透传到 %s，请求路径: %s", addr, path)
}

// 类型转换函数
func Getalarm_type(alarmType string) string {
	descMap := map[string]string{
		"all":            "所有车牌都报警",
		"new_energy":     "新能源车牌",
		"non_new_energy": "非新能源车牌",
		"plate_number":   "车牌号报警",
		"plate_no":       "车牌号",
	}
	return descMap[alarmType]
}
func Getplate_type(plateType int) string {
	descMap := map[int]string{
		0:  "无牌车",
		1:  "大型汽车号牌车",
		2:  "小型汽车号牌车",
		3:  "使馆汽车号牌",
		4:  "领馆汽车号牌",
		5:  "挂车号牌",
		6:  "教练车号牌",
		7:  "教练车号牌",
		8:  "香港出入境号牌",
		9:  "澳门出入境号牌",
		10: "武警号牌",
		11: "军队号牌",
		12: "新能源号牌",
		13: " 其它号牌 ",
	}
	return descMap[plateType]
}
func Getplate_color(plateColor int) string {
	descMap := map[int]string{
		0: "未知",
		1: "蓝牌",
		2: "黄牌",
		3: "绿牌",
		4: "黑牌",
		5: "白牌",
	}
	return descMap[plateColor]
}

func Getvehicle_type(vehicleType int) string {
	descMap := map[int]string{
		0:  "未知",
		1:  "小轿车",
		2:  "SUV",
		3:  "面包车",
		4:  "卡车",
		5:  "自行车 ",
		6:  "电动车/摩托车",
		7:  "三轮车",
		8:  "客车",
		9:  "皮卡车",
		10: "货车",
	}
	return descMap[vehicleType]
}

func Getvehicle_color(vehicleColor int) string {
	descMap := map[int]string{
		0: "未知",
		1: "黑色",
		2: "蓝色",
		3: "棕色",
		4: "灰色",
		5: "黄色",
		6: "绿色",
		7: "紫色",
		8: "红色",
		9: "白色",
	}
	return descMap[vehicleColor]
}
func Getvehicle_orient(vehicleOrient int) string {
	descMap := map[int]string{
		0: "未知",
		1: "正面",
		2: "背面",
		3: "侧面",
	}
	return descMap[vehicleOrient]
}

// 验证事件报告数据
func validateEventReport(data OriginalEventReportMessage) error {
	if data.Method != "event_report" {
		return fmt.Errorf("无效的方法: %s", data.Method)
	}

	if data.Param.DeviceID == "" {
		return fmt.Errorf("设备ID不能为空")
	}

	if data.Param.Time == "" {
		return fmt.Errorf("时间不能为空")
	}

	if data.Param.Type == "" {
		return fmt.Errorf("事件类型不能为空")
	}

	return nil
}

// 对象池优化内存使用
var imageBufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// UI更新消息类型
type UIUpdateMessage struct {
	Type        string
	JSONData    string
	ImageData   string
	ImageStatus string
	APIEndpoint string
}

// 全局状态管理
type AppState struct {
	currentImage  *canvas.Image
	imageData     string // 存储base64图片数据
	deviceID      string // 存储设备ID
	eventTime     string // 存储事件时间
	jsonData      string
	currentStatus string       // 存储当前状态
	apiEndpoint   string       // 存储API接口信息
	mutex         sync.RWMutex // 使用读写锁提高并发性能
}

// 透传URL相关全局变量
var (
	forwardURL string
)

// UI更新通道
var uiUpdateChannel = make(chan UIUpdateMessage, 10)

var appState = AppState{}

func (s *AppState) UpdateImageData(imageData, deviceID, eventTime string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.imageData = imageData
	s.deviceID = deviceID
	s.eventTime = eventTime
}

func (s *AppState) GetImageData() (string, string, string) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.imageData, s.deviceID, s.eventTime
}

func (s *AppState) UpdateJSONData(jsonData, currentStatus, apiEndpoint string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.jsonData = jsonData
	s.currentStatus = currentStatus
	s.apiEndpoint = apiEndpoint
}

func (s *AppState) GetJSONData() (string, string, string) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.jsonData, s.currentStatus, s.apiEndpoint
}

// handleStopState 处理stop状态
func handleStopState(imageContainer *fyne.Container, imageLabel *widget.Label, jsonLabel *widget.Label, imageData string) {
	if imageData != "" {
		// 有图片数据时显示图片
		handleImageDisplay(imageData, imageContainer, imageLabel)
	} else {
		// 没有图片数据时显示"无图"
		imageLabel.SetText("无图")
		imageContainer.Objects = []fyne.CanvasObject{imageLabel}
		imageContainer.Refresh()
	}

	// 三秒后清空JSON显示和图片显示，重置为初始状态
	go func() {
		time.Sleep(6 * time.Second)
		jsonLabel.SetText("等待JSON数据...")
		// 清空图片显示区域，重置为初始状态
		imageLabel.SetText("等待图片数据...")
		imageContainer.Objects = []fyne.CanvasObject{imageLabel}
		imageContainer.Refresh()
		appState.UpdateJSONData("", "", "")
		appState.UpdateImageData("", "", "")
		logDebug("Stop状态: 6秒后清空JSON和图片显示，重置为初始状态")
	}()
}

// handleImageDisplay 处理图片显示
func handleImageDisplay(imageData string, imageContainer *fyne.Container, imageLabel *widget.Label) {
	// 解码并显示图片
	if img, err := decodeBase64Image(imageData); err == nil {
		// 创建Fyne图片资源
		var buf bytes.Buffer
		jpeg.Encode(&buf, img, nil)

		// 从字节数据创建图片资源
		resource := fyne.NewStaticResource("event_image.jpg", buf.Bytes())
		imageWidget := canvas.NewImageFromResource(resource)
		imageWidget.FillMode = canvas.ImageFillContain
		imageWidget.SetMinSize(fyne.NewSize(400, 300))

		// 更新图片容器
		imageContainer.Objects = []fyne.CanvasObject{imageWidget}
		imageContainer.Refresh()
	} else {
		imageLabel.SetText(fmt.Sprintf("图片解码错误: %v", err))
		imageContainer.Objects = []fyne.CanvasObject{imageLabel}
		imageContainer.Refresh()
	}
}

type EventReportMessage struct {
	Method string `json:"method"`
	Param  struct {
		DeviceID   string `json:"device_id"`
		DeviceName string `json:"device_name"`
		//ChannelType int             `json:"channel_type"`
		Alarm_type string `json:"alarm_type"`
		ChannelID  int    `json:"channel_id"`
		//Event       int             `json:"event"`
		//Type        string          `json:"type"`
		//TypeName    string          `json:"typeName"`
		Time       string `json:"time"`
		Status     string `json:"status"`
		Alarm_uuid string `json:"alarm_uuid"`
		//Extern      json.RawMessage `json:"extern"`
		JpegBase64 string `json:"jpeg_base64"`
	}
}

// 获取本地网络接口
func getLocalIPs() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ips []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.To4() == nil {
				continue
			}

			ips = append(ips, ip.String())
		}
	}

	return ips, nil
}

// 启动HTTP服务器
// 定义Extern数据结构体
type ExternData struct {
	PlateNo       string `json:"plate_no"`
	AlarmType     string `json:"alarm_type"`
	PlateType     int    `json:"plate_type"`
	PlateColor    int    `json:"plate_color"`
	VehicleType   int    `json:"vehicle_type"`
	VehicleColor  int    `json:"vehicle_color"`
	VehicleOrient int    `json:"vehicle_orient"`
}

// 定义原始事件报告消息结构体
type OriginalEventReportMessage struct {
	Method string `json:"method"`
	Param  struct {
		DeviceID    string          `json:"device_id"`
		DeviceName  string          `json:"device_name"`
		ChannelType int             `json:"channel_type"`
		ChannelID   int             `json:"channel_id"` // 添加ChannelID字段
		Event       int             `json:"event"`
		Type        string          `json:"type"`
		TypeName    string          `json:"typeName"`
		Time        string          `json:"time"`
		Status      int             `json:"status"`
		Extern      json.RawMessage `json:"extern"`
		JpegBase64  string          `json:"jpeg_base64"`
	}
}

func startServer(ip string, port string, onError func(error)) {
	// 禁用日志输出
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery()) // 只使用恢复中间件，

	// 全局中间件 - 透传所有请求数据
	r.Use(func(c *gin.Context) {
		// 读取原始数据
		data, _ := c.GetRawData()

		// 透传原始数据，包含请求路径
		forwardData(data, c.Request.URL.Path)

		// 将数据重新放回请求体，以便后续处理
		c.Request.Body = io.NopCloser(bytes.NewBuffer(data))

		// 继续处理请求
		c.Next()
	})

	//v1/uns/reviceMonitorPointRecord/alarm_report
	r.POST("/v1/uns/reviceMonitorPointRecord/alarm_report", func(c *gin.Context) {
		data, err := c.GetRawData()
		if err != nil || len(data) == 0 {

			c.JSON(http.StatusBadRequest, gin.H{"错误": "未接收到数据"})
			return
		}

		// 打印完整的原始JSON数据
		logDebug("接收到的原始JSON数据: %s", string(data))

		var message EventReportMessage
		if err := json.Unmarshal(data, &message); err != nil {

			logError("JSON解析失败", err)
			c.JSON(http.StatusBadRequest, gin.H{"错误": "JSON格式无效"})
			return
		}

		//保存原始文件，在DeviceID文件夹下保存，和图片文件时间保持一致，方便后续分析
		deviceDir := filepath.Join("./original", message.Param.DeviceID)

		if err := os.MkdirAll(deviceDir, 0755); err != nil {
			logError("创建设备目录失败", err)
			c.JSON(http.StatusInternalServerError, gin.H{"错误": "内部服务器错误"})
			return
		}
		// 使用与图片文件相同的时间格式保存原始JSON数据
		safeTime := formatTimeForFileName(message.Param.Time)
		originalJsonPath := filepath.Join(deviceDir, fmt.Sprintf("%s.json", safeTime))
		if err := os.WriteFile(originalJsonPath, data, 0644); err != nil {
			logError("保存原始JSON数据失败", err)
		} else {
			logDebug("原始JSON数据已保存: %s", originalJsonPath)
			// 清理超过100个的最老文件
			cleanupOldFiles(deviceDir, 100)
		}

		// 更新状态为正常

		// 解析JSON数据 - 使用工具函数
		type EventInfo struct {
			EventTime  string `json:"event_time"`
			DeviceID   string `json:"device_id"`
			DeviceName string `json:"device_name"`
			Alarm_type string `json:"alarm_type"`
			Alarm_uuid string `json:"alarm_uuid"`
			Status     string `json:"status"`
		}

		statusStr := getStatusStringString(message.Param.Status)
		logDebug("接收到消息 - 状态: %s, 时间: %s", statusStr, message.Param.Time)

		info := EventInfo{
			EventTime:  message.Param.Time,
			DeviceID:   message.Param.DeviceID,
			DeviceName: message.Param.DeviceName,
			Alarm_type: message.Param.Alarm_type,
			Alarm_uuid: message.Param.Alarm_uuid,
			Status:     statusStr,
		}

		jsonData, err := json.MarshalIndent(info, "", "  ")
		if err == nil {
			logDebug("设置状态 - currentStatus: %s", statusStr)

			// 保存JSON数据 - 使用工具函数
			parsedJsonDir := filepath.Join("./json", message.Param.DeviceID)
			if err := os.MkdirAll(parsedJsonDir, 0755); err == nil {
				safeTime := formatTimeForFileName(message.Param.Time)
				parsedJsonPath := filepath.Join(parsedJsonDir, fmt.Sprintf("%s.json", safeTime))
				if err := os.WriteFile(parsedJsonPath, jsonData, 0644); err != nil {
					logError("保存JSON数据失败", err)
				}
				// 清理超过100个的最老文件
				cleanupOldFiles(parsedJsonDir, 100)
			}

			// 处理图片数据并与JSON数据一起更新UI
			imageData := message.Param.JpegBase64
			logDebug("JpegBase64字段长度: %d, 内容: %s", len(imageData), imageData)

			if strings.TrimSpace(imageData) != "" {
				logDebug("开始处理图片数据")
				if _, err := decodeBase64Image(imageData); err == nil {
					logDebug("图片解码成功，准备保存")
					// 保存图片 - 使用与JSON相同的时间戳和设备ID
					if err := saveImageWithTime(imageData, formatTimeForFileName(message.Param.Time), message.Param.DeviceID); err != nil {
						logError("保存图片失败", err)
					} else {
						logDebug("图片保存成功")
					}
				} else {
					logError("图片解码失败", err)
					// 图片解码失败，视为无图
					imageData = ""
				}
			} else {
				logDebug("JpegBase64字段为空或只包含空格")
				// 无图片数据，设置为空
				imageData = ""
			}

			// 同时更新JSON数据和图片数据（可能为空）到状态
			appState.UpdateJSONData(string(jsonData), statusStr, "/v1/uns/reviceMonitorPointRecord/alarm_report")
			appState.UpdateImageData(imageData, message.Param.DeviceID, message.Param.Time)
		} else {
			logError("JSON序列化失败", err)
		}

		c.JSON(http.StatusOK, gin.H{"状态": "成功"})
	})

	// 接口 - /v1/device/event_report
	r.POST("/v1/device/event_report", func(c *gin.Context) {
		data, err := c.GetRawData()
		if err != nil || len(data) == 0 {

			c.JSON(http.StatusBadRequest, gin.H{"错误": "未接收到数据"})
			return
		}

		// 打印完整的原始JSON数据
		logDebug("接收到的原始JSON数据: %s", string(data))

		var message OriginalEventReportMessage
		if err := json.Unmarshal(data, &message); err != nil {

			logError("JSON解析失败", err)
			c.JSON(http.StatusBadRequest, gin.H{"错误": "JSON格式无效"})
			return
		}

		//保存原始文件，和图片文件时间保持一致，方便后续分析
		deviceDir := filepath.Join("./original", message.Param.DeviceID)
		if err := os.MkdirAll(deviceDir, 0755); err != nil {
			logError("创建设备目录失败", err)
			c.JSON(http.StatusInternalServerError, gin.H{"错误": "内部服务器错误"})
			return
		}
		// 使用与图片文件相同的时间格式保存原始JSON数据
		safeTime := formatTimeForFileName(message.Param.Time)
		originalJsonPath := filepath.Join(deviceDir, fmt.Sprintf("%s.json", safeTime))
		if err := os.WriteFile(originalJsonPath, data, 0644); err != nil {
			logError("保存原始JSON数据失败", err)
		} else {
			logDebug("原始JSON数据已保存: %s", originalJsonPath)
			// 清理超过100个的最老文件
			cleanupOldFiles(deviceDir, 100)
		}

		// 验证事件报告数据
		if err := validateEventReport(message); err != nil {

			logError("验证事件报告失败", err)
			c.JSON(http.StatusBadRequest, gin.H{"错误": err.Error()})
			return
		}

		// 更新状态为正常

		// 更新连接状态

		// 解析Extern字段（base64编码的JSON）
		var externData ExternData
		if len(message.Param.Extern) > 0 {
			externBase64 := strings.Trim(string(message.Param.Extern), "\"")
			decodedExtern, err := base64.StdEncoding.DecodeString(externBase64)
			if err == nil {
				if err := json.Unmarshal(decodedExtern, &externData); err != nil {
					logError("解析Extern数据失败", err)
				}
			} else {
				logError("解码Extern数据失败", err)
			}
		}

		statusStr := getStatusStringInt(message.Param.Status)
		logDebug("接收到原始消息 - 状态: %s, 时间: %s, 设备ID: %s", statusStr, message.Param.Time, message.Param.DeviceID)

		// 检查extern字段是否为空
		externIsEmpty := len(message.Param.Extern) == 0 || string(message.Param.Extern) == `""`

		// 根据extern是否为空决定使用不同的结构体
		var jsonData []byte

		if externIsEmpty {
			// extern为空，只包含基本的事件信息
			type BasicEventInfo struct {
				EventTime  string `json:"event_time"`
				DeviceID   string `json:"device_id"`
				DeviceName string `json:"device_name"`
				EventType  string `json:"event_type"`
				EventName  string `json:"event_name"`
				Status     string `json:"status"`
			}

			info := BasicEventInfo{
				EventTime:  message.Param.Time,
				DeviceID:   message.Param.DeviceID,
				DeviceName: message.Param.DeviceName,
				EventType:  message.Param.Type,
				EventName:  message.Param.TypeName,
				Status:     statusStr,
			}

			jsonData, err = json.MarshalIndent(info, "", "  ")
		} else {
			// extern不为空，包含完整的解析内容
			// 获取类型描述
			alarmTypeDesc := Getalarm_type(externData.AlarmType)
			plateTypeDesc := Getplate_type(externData.PlateType)
			plateColorDesc := Getplate_color(externData.PlateColor)
			vehicleTypeDesc := Getvehicle_type(externData.VehicleType)
			vehicleColorDesc := Getvehicle_color(externData.VehicleColor)
			vehicleOrientDesc := Getvehicle_orient(externData.VehicleOrient)

			logInfo("信息: %s %s %s %s %s %s %s %s %s %s", message.Param.DeviceID, message.Param.DeviceName, message.Param.TypeName, alarmTypeDesc, externData.PlateNo, plateTypeDesc, plateColorDesc, vehicleTypeDesc, vehicleColorDesc, vehicleOrientDesc)

			type FullEventInfo struct {
				EventTime     string `json:"event_time"`
				DeviceID      string `json:"device_id"`
				DeviceName    string `json:"device_name"`
				EventType     string `json:"event_type"`
				EventName     string `json:"event_name"`
				Status        string `json:"status"`
				PlateNo       string `json:"plate_no"`
				AlarmType     string `json:"alarm_type"`
				PlateType     string `json:"plate_type"`
				PlateColor    string `json:"plate_color"`
				VehicleType   string `json:"vehicle_type"`
				VehicleColor  string `json:"vehicle_color"`
				VehicleOrient string `json:"vehicle_orient"`
			}

			info := FullEventInfo{
				EventTime:     message.Param.Time,
				DeviceID:      message.Param.DeviceID,
				DeviceName:    message.Param.DeviceName,
				EventType:     message.Param.Type,
				EventName:     message.Param.TypeName,
				Status:        statusStr,
				PlateNo:       externData.PlateNo,
				AlarmType:     alarmTypeDesc,
				PlateType:     plateTypeDesc,
				PlateColor:    plateColorDesc,
				VehicleType:   vehicleTypeDesc,
				VehicleColor:  vehicleColorDesc,
				VehicleOrient: vehicleOrientDesc,
			}

			jsonData, err = json.MarshalIndent(info, "", "  ")
		}

		if err == nil {
			logDebug("设置状态 - currentStatus: %s", statusStr)

			// 保存JSON数据
			parsedJsonDir := filepath.Join("./json", message.Param.DeviceID)
			if err := os.MkdirAll(parsedJsonDir, 0755); err == nil {
				safeTime := formatTimeForFileName(message.Param.Time)
				parsedJsonPath := filepath.Join(parsedJsonDir, fmt.Sprintf("%s.json", safeTime))
				if err := os.WriteFile(parsedJsonPath, jsonData, 0644); err != nil {
					logError("保存JSON数据失败", err)
				}
				// 清理超过100个的最老文件
				cleanupOldFiles(parsedJsonDir, 100)
			}

			// 处理图片数据并与JSON数据一起更新UI
			imageData := message.Param.JpegBase64

			if strings.TrimSpace(imageData) != "" {
				if _, err := decodeBase64Image(imageData); err == nil {
					// 保存图片 - 使用与JSON相同的时间戳和设备ID
					if err := saveImageWithTime(imageData, formatTimeForFileName(message.Param.Time), message.Param.DeviceID); err != nil {
						logError("保存图片失败", err)
					}
				} else {
					logError("图片解码失败", err)
					// 图片解码失败，视为无图
					imageData = ""
				}
			} else {
				// 无图片数据，设置为空
				imageData = ""
			}

			// 同时更新JSON数据和图片数据（可能为空）到状态
			appState.UpdateJSONData(string(jsonData), statusStr, "/v1/device/event_report")
			appState.UpdateImageData(imageData, message.Param.DeviceID, message.Param.Time)
		} else {
			logError("JSON序列化失败", err)
		}

		c.JSON(http.StatusOK, gin.H{"状态": "成功"})
	})

	r.POST("/v1/device/keepalive", func(c *gin.Context) {
		// 打印心跳包原始数据
		data, _ := c.GetRawData()
		logDebug("收到心跳包，原始数据: %s", string(data))

		// 更新状态为正常

		c.JSON(http.StatusOK, gin.H{
			"状态": "在线",
			"消息": "设备在线",
		})
	})

	// 启动HTTP服务器
	addr := fmt.Sprintf("%s:%s", ip, port)

	// 处理所有未定义路径的请求，透传数据并返回200响应
	r.NoRoute(func(c *gin.Context) {
		// 透传已在全局中间件处理
		c.JSON(http.StatusOK, gin.H{"状态": "成功"})
	})

	if err := r.Run(addr); err != nil {
		onError(err)
	}
}

// 优化的Base64图片解码
func decodeBase64Image(base64Str string) (image.Image, error) {
	// 移除可能的前缀
	base64Str = strings.TrimSpace(base64Str)
	if strings.HasPrefix(base64Str, "data:image/jpeg;base64,") {
		base64Str = strings.TrimPrefix(base64Str, "data:image/jpeg;base64,")
	}

	// 使用对象池获取缓冲区
	buf := imageBufferPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		imageBufferPool.Put(buf)
	}()

	// 解码base64数据
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(base64Str))
	_, err := buf.ReadFrom(decoder)
	if err != nil {
		return nil, fmt.Errorf("base64解码失败: %v", err)
	}

	// 解码JPEG图片
	img, err := jpeg.Decode(buf)
	if err != nil {
		return nil, fmt.Errorf("JPEG解码失败: %v", err)
	}

	return img, nil
}

func main() {
	// 设置中文字符编码和字体
	os.Setenv("LANG", "zh_CN.UTF-8")
	os.Setenv("LC_ALL", "zh_CN.UTF-8")
	os.Setenv("FYNE_FONT", "C:\\Windows\\Fonts\\simhei.ttf")

	// 创建Fyne应用
	myApp := app.New()
	myWindow := myApp.NewWindow("HTTP接收解析")
	myWindow.Resize(fyne.NewSize(1000, 600))

	// 创建顶部提示条幅（两行文本）
	promptText1 := canvas.NewText("设备需开启Http推送", color.RGBA{R: 0, G: 0, B: 255, A: 255})
	promptText2 := canvas.NewText("添加Http推送地址：", color.RGBA{R: 255, G: 0, B: 0, A: 255})
	promptText1.TextSize = 16
	promptText2.TextSize = 24
	promptText1.TextStyle = fyne.TextStyle{Bold: true}
	promptText2.TextStyle = fyne.TextStyle{Bold: true}

	// 使用垂直容器显示两行文本
	promptContent := container.NewVBox(
		container.NewCenter(promptText1),
		container.NewCenter(promptText2),
	)
	promptContainer := container.NewCenter(promptContent)

	// 调整容器高度以适应两行文本
	promptContainer.Resize(fyne.NewSize(800, 100))

	// 添加PDF查看按钮
	pdfButton := widget.NewButton("查看接口说明", func() {
		// 从嵌入的文件系统中读取PDF内容
		pdfData, err := pdfFile.ReadFile("HTTP推送接口说明.pdf")
		if err != nil {
			logError("读取嵌入的PDF文件失败", err)
			dialog.ShowError(fmt.Errorf("读取PDF文件失败: %v", err), myWindow)
			return
		}

		// 创建临时文件
		tempFile, err := ioutil.TempFile("", "HTTP推送接口说明_*.pdf")
		if err != nil {
			logError("创建临时文件失败", err)
			dialog.ShowError(fmt.Errorf("创建临时文件失败: %v", err), myWindow)
			return
		}
		tempPath := tempFile.Name()
		defer tempFile.Close()

		// 写入PDF内容
		if _, err := tempFile.Write(pdfData); err != nil {
			logError("写入临时文件失败", err)
			dialog.ShowError(fmt.Errorf("写入临时文件失败: %v", err), myWindow)
			return
		}

		// 使用系统默认程序打开临时PDF文件
		cmd := exec.Command("cmd", "/c", "start", "", tempPath)
		if err := cmd.Start(); err != nil {
			logError("打开PDF失败", err)
			dialog.ShowError(fmt.Errorf("打开PDF失败: %v", err), myWindow)
		}
	})

	// 左侧图片显示区域 - 使用占位符
	imageLabel := widget.NewLabel("等待图片数据...")
	imageLabel.Alignment = fyne.TextAlignCenter
	imageContainer := container.NewCenter(imageLabel)

	// 右侧JSON数据显示区域
	jsonLabel := widget.NewLabel("等待JSON数据...")
	jsonLabel.Alignment = fyne.TextAlignLeading // 左对齐，符合JSON数据阅读习惯
	// 使用垂直居中容器，让JSON数据在垂直方向上居中
	jsonCenter := container.NewCenter(jsonLabel)
	jsonScroll := container.NewScroll(jsonCenter) // 滚动容器中嵌套居中容器
	jsonScroll.SetMinSize(fyne.NewSize(500, 500))

	// 底部条幅
	bottomBannerText := canvas.NewText("文件夹内容：图片images、数据json、源数据original				支持通用目标检测（移动侦测、区域入侵、遮挡报警、烟火）和车牌检测", color.RGBA{R: 0, G: 0, B: 255, A: 255})
	bottomBannerText.TextSize = 14
	bottomBannerText.TextStyle = fyne.TextStyle{Bold: true}
	bottomBannerContainer := container.NewCenter(bottomBannerText)
	bottomBannerContainer.Resize(fyne.NewSize(800, 50))

	// 主内容区域（图片和JSON）
	hsplit := container.NewHSplit(imageContainer, jsonScroll)

	// 创建主内容区域，包含提示信息、分割视图和底部条幅
	mainContent := container.NewVBox(
		promptContainer,
		hsplit,
		bottomBannerContainer,
	)

	// 添加透传IP地址按钮
	forwardButton := widget.NewButton("透传IP地址", func() {
		// 创建URL输入框
		urlEntry := widget.NewEntry()
		urlEntry.SetPlaceHolder("例如：http://192.168.1.100:8081/api/get")
		urlEntry.SetText(forwardURL)

		// 创建表单
		form := dialog.NewForm(
			"设置透传URL地址",
			"确定",
			"取消",
			[]*widget.FormItem{
				{Text: "URL地址", Widget: urlEntry},
			},
			func(ok bool) {
				if ok {
					forwardURL = urlEntry.Text
					logInfo("透传URL地址已设置: %s", forwardURL)
				}
			},
			myWindow,
		)
		form.Resize(fyne.NewSize(500, 150))
		form.Show()
	})

	// 创建右上角按钮组，垂直排列两个按钮
	topRightButtons := container.NewVBox(
		pdfButton,
		forwardButton, // 添加透传IP地址按钮
	)

	// 创建右上角容器，使用水平布局将按钮组推到右侧
	topRightContainer := container.NewHBox(
		layout.NewSpacer(),                   // 左侧占位，将按钮推到右侧
		container.NewPadded(topRightButtons), // 添加边距
	)

	// 使用Max布局将按钮容器叠加在主内容上方，实现右上角定位
	content := container.NewMax(
		mainContent,
		topRightContainer,
	)

	// 获取本地网络接口
	ips, err := getLocalIPs()
	if err != nil {
		dialog.ShowError(fmt.Errorf("获取网络接口失败: %v", err), myWindow)
		return
	}

	if len(ips) == 0 {
		dialog.ShowInformation("错误", "未找到可用的网络接口", myWindow)
		return
	}

	// 创建IP选择对话框
	ipSelect := widget.NewSelect(ips, nil)
	ipSelect.SetSelected(ips[0])
	portEntry := widget.NewEntry()
	portEntry.SetText("8181")
	portEntry.Validator = func(s string) error {
		if s == "" {
			return fmt.Errorf("端口不能为空")
		}
		return nil
	}

	// 创建表单项目
	ipItem := widget.NewFormItem("IP地址", ipSelect)
	portItem := widget.NewFormItem("端口", portEntry)

	form := dialog.NewForm(
		"选择监听地址",
		"启动服务",
		"取消",
		[]*widget.FormItem{ipItem, portItem},
		func(ok bool) {
			if !ok {
				myApp.Quit()
				return
			}

			// 获取用户选择的IP和端口
			selectedIP := ipSelect.Selected
			selectedPort := portEntry.Text

			// 更新顶部提示条幅第二行内容
			promptText2.Text = fmt.Sprintf("并添加Http推送地址：http://%s:%s", selectedIP, selectedPort)
			promptText2.Refresh()

			// 启动服务器
			go startServer(selectedIP, selectedPort, func(err error) {
				dialog.ShowError(fmt.Errorf("服务器启动失败: %v", err), myWindow)
				myApp.Quit()
			})

			// 定时更新UI状态
			go func() {
				ticker := time.NewTicker(1 * time.Second)
				defer ticker.Stop()

				for range ticker.C {
					// 获取数据
					jsonData, currentImageStatus, apiEndpoint := appState.GetJSONData()
					imageData, _, _ := appState.GetImageData()

					// 发送UI更新消息到主线程
					uiUpdateChannel <- UIUpdateMessage{
						Type:        "status_update",
						JSONData:    jsonData,
						ImageData:   imageData,
						ImageStatus: currentImageStatus,
						APIEndpoint: apiEndpoint,
					}
				}
			}()
		},
		myWindow,
	)

	form.Resize(fyne.NewSize(400, 200))
	form.Show()

	// 设置窗口内容
	myWindow.SetContent(content)

	// 启动UI更新处理器
	go func() {
		for msg := range uiUpdateChannel {
			switch msg.Type {
			case "status_update":
				// 处理JSON数据和图片显示
				if msg.JSONData != "" {
					// 更新JSON数据，包含接口信息
					if msg.APIEndpoint != "" {
						jsonLabel.SetText(fmt.Sprintf("收到: %s\n\n%s", msg.APIEndpoint, msg.JSONData))
					} else {
						jsonLabel.SetText(msg.JSONData)
					}
					appState.UpdateJSONData("", "", "")

					// 处理图片显示
					if msg.ImageStatus == "stop" {
						handleStopState(imageContainer, imageLabel, jsonLabel, msg.ImageData)
					} else {
						if msg.ImageData != "" {
							// 有图片时显示图片
							handleImageDisplay(msg.ImageData, imageContainer, imageLabel)
							// 清空图片数据
							appState.UpdateImageData("", "", "")
						} else {
							// 没有图片时显示"无图"
							imageLabel.SetText("无图")
							imageContainer.Objects = []fyne.CanvasObject{imageLabel}
							imageContainer.Refresh()
						}
					}
				} else {
					// 处理stop状态
					if msg.ImageStatus == "stop" {
						handleStopState(imageContainer, imageLabel, jsonLabel, msg.ImageData)
					}
				}

			}
		}
	}()

	myWindow.ShowAndRun()
}

// saveImage 保存图片到文件
func saveImage(base64Data string, deviceID string) error {
	return saveImageWithTime(base64Data, time.Now().Format("20060102_150405"), deviceID)
}

// saveImageWithTime
func saveImageWithTime(base64Data string, timestamp string, deviceID string) error {
	// 移除可能的base64前缀
	if idx := strings.Index(base64Data, "base64,"); idx != -1 {
		base64Data = base64Data[idx+7:]
	}

	// 使用对象池获取缓冲区
	buffer := imageBufferPool.Get().(*bytes.Buffer)
	defer func() {
		buffer.Reset()
		imageBufferPool.Put(buffer)
	}()

	// 流式解码base64数据
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(base64Data))

	// 直接解码到图片
	img, _, err := image.Decode(decoder)
	if err != nil {
		return fmt.Errorf("图片解码失败: %v", err)
	}

	// 创建文件名（使用工具函数）- 与JSON文件使用相同的命名格式
	filename := fmt.Sprintf("%s.jpg", formatTimeForFileName(timestamp))
	imageFilePath := filepath.Join("images", deviceID, filename)

	// 确保设备图片目录存在
	if err := os.MkdirAll("images/"+deviceID, 0755); err != nil {
		return fmt.Errorf("创建设备图片目录失败: %v", err)
	}

	// 创建文件
	file, err := os.Create(imageFilePath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	// 保存为JPEG格式
	err = jpeg.Encode(file, img, &jpeg.Options{Quality: 90})
	if err != nil {
		return fmt.Errorf("保存图片失败: %v", err)
	}

	logInfo(fmt.Sprintf("图片已保存: %s/%s", deviceID, filename))
	// 清理超过100个的最老文件
	imageDir := filepath.Join("images", deviceID)
	cleanupOldFiles(imageDir, 100)
	return nil
}
