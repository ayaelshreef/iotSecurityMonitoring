# IoT Security Monitoring System

A comprehensive Django-based web application designed to monitor, analyze, and secure IoT devices on your network. This system provides real-time network scanning, anomaly detection, packet capture, and security alerting capabilities.

## 🚀 Features

### 🔍 Network Discovery & Device Management

- **Automatic Network Scanning**: Scans your network to discover active IoT devices using ARP scanning
- **Device Registration**: Automatically adds newly discovered devices to the database
- **Manual Device Addition**: Support for manually adding devices by IP or MAC address
- **Device Status Monitoring**: Tracks active/inactive status of all registered devices
- **Device Information Display**: Shows detailed information including:
  - Device name and IP address
  - MAC address and manufacturer identification
  - Network protocols used
  - Connected IP addresses
  - Training status and performance metrics

### 📊 Real-time Dashboard

- **Device Overview**: Visual dashboard showing all registered devices
- **Status Indicators**: Color-coded status badges for active/inactive and trained/untrained devices
- **Quick Actions**: Edit and delete device functionality directly from the dashboard
- **Responsive Design**: Modern, mobile-friendly interface

### 🛡️ Security Monitoring & Anomaly Detection

#### Training System
- **Configurable Training Time**: Set training duration for devices (default: 10 minutes)
- **Automated Training**: Devices automatically learn normal behavior patterns
- **Training Progress Tracking**: Monitor training status for each device

#### Anomaly Detection Parameters
- **Volume Monitoring**: Detects unusual data transfer volumes
- **Speed Analysis**: Monitors packet transmission rates
- **User Activity**: Tracks number of unique users/connections
- **Protocol Analysis**: Monitors for unauthorized or suspicious protocols

#### Alert System
- **Real-time Notifications**: Instant alerts for detected anomalies
- **Parameter-specific Alerts**: Different alert types for volume, speed, protocol, and IP anomalies
- **Notification Management**: Mark alerts as read/unread
- **Alert History**: Complete log of all security events

### 📦 Packet Capture & Analysis

- **Real-time Packet Capture**: Live packet sniffing for active devices
- **Filtered Capture**: Captures only packets involving the monitored device
- **Packet Details**: Shows timestamp, source/destination IPs, protocol, and packet size
- **Start/Stop Controls**: Easy-to-use controls for packet capture sessions
- **Historical Data**: Stores captured packets for analysis

### ⚙️ Settings & Configuration

#### Training Configuration
- **Global Training Time**: Set training duration for all devices
- **Training Status Display**: View current training minutes setting
- **Training Progress**: Real-time updates on training completion

#### Notification Management
- **Notification Log**: Complete history of all notifications
- **Read Status Tracking**: Track which notifications have been viewed
- **Auto-mark as Read**: Automatically mark notifications as read when viewing Security Alerts

#### Report Generation
- **PDF Export**: Generate comprehensive PDF reports
- **Device Archive**: Complete device information including:
  - System overview with key metrics
  - Detailed device information tables
  - Security alerts history
  - Visual status indicators
- **Downloadable Reports**: PDF reports with timestamp for record keeping

### 🔄 Background Processing

#### Celery Integration
- **Automated Tasks**: Background processing for device monitoring
- **Scheduled Scans**: Periodic network scanning (every minute)
- **Training Automation**: Automated training tasks (every 5 minutes)
- **Real-time Processing**: Continuous monitoring without blocking the UI

#### Task Management
- **Device Status Updates**: Regular updates of device active/inactive status
- **Parameter Monitoring**: Continuous monitoring of device behavior
- **Anomaly Checking**: Real-time analysis of device parameters against trained baselines

### 📡 Real-time Features

- **WebSocket Support**: Real-time notification delivery
- **Live Updates**: Dashboard updates without page refresh
- **Instant Alerts**: Immediate notification of security events
- **Auto-refresh**: Periodic data updates for continuous monitoring

## 🛠️ Technical Architecture

### Backend Technologies
- **Django 5.1.3**: Web framework
- **SQLite**: Database for storing device and notification data
- **Celery**: Asynchronous task processing
- **Redis**: Message broker for Celery
- **Scapy**: Network packet manipulation and analysis

### Frontend Technologies
- **Bootstrap 4.5.2**: Responsive UI framework
- **jQuery**: JavaScript functionality
- **WebSocket**: Real-time communication
- **AJAX**: Asynchronous data updates

### Security Features
- **CSRF Protection**: Django's built-in CSRF protection
- **Data Validation**: Input validation and sanitization
- **Error Handling**: Comprehensive error handling and logging
- **Secure Communications**: HTTPS support ready

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8+
- Redis server
- Network interface with monitoring capabilities

### Installation Steps

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd iotSecurityMonitoring
   ```

2. **Create virtual environment**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   # source .venv/bin/activate  # Linux/Mac
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Database setup**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

5. **Start Redis server**
   ```bash
   redis-server
   ```

6. **Start Celery worker** (in separate terminal)
   ```bash
   celery -A data worker -l info
   ```

7. **Start Celery beat** (in separate terminal)
   ```bash
   celery -A data beat -l info
   ```

8. **Run Django server**
   ```bash
   python manage.py runserver
   ```

## 📖 Usage Guide

### Initial Setup
1. Access the application at `http://127.0.0.1:8000/`
2. Click "Scan Devices" to discover IoT devices on your network
3. Configure training time in Settings (default: 10 minutes)
4. Let devices train to establish baseline behavior

### Monitoring Devices
1. View all devices on the main dashboard
2. Click on device IP addresses to view detailed packet capture
3. Monitor Security Alerts dropdown for real-time notifications
4. Use Settings page to view notification history and generate reports

### Packet Capture
1. Navigate to a device's packet page
2. Click "Start Capture" to begin monitoring
3. View real-time packet data in the table
4. Click "Stop Capture" to end the session

### Report Generation
1. Go to Settings page
2. Navigate to the Reports section
3. Click "Export Report" to generate PDF
4. Download includes device details and security alerts

## 🔧 Configuration

### Training Time
- Default: 10 minutes per device
- Configurable via Settings page
- Applied to all new devices

### Network Interface
- Automatically detects Wi-Fi and Ethernet interfaces
- Supports Windows and Linux/Unix systems
- Configurable network scanning parameters

### Alert Thresholds
- Volume: Monitors data transfer rates
- Speed: Tracks packet transmission speeds
- Protocols: Detects unauthorized protocol usage
- IP Addresses: Monitors for suspicious connections

## 🐛 Troubleshooting

### Common Issues

1. **Packet Capture Not Working**
   - Ensure you have administrator/root privileges
   - Check if the network interface supports monitoring mode
   - Verify device is active and on the same network

2. **Celery Tasks Not Running**
   - Ensure Redis server is running
   - Check Celery worker and beat are started
   - Verify task scheduling configuration

3. **Device Not Detected**
   - Check if device is on the same network subnet
   - Verify device responds to ARP requests
   - Try manual device addition by IP or MAC address

4. **PDF Generation Issues**
   - Ensure ReportLab is properly installed
   - Check for sufficient disk space
   - Verify write permissions in the application directory

## 📊 System Requirements

### Minimum Requirements
- Python 3.8+
- 2GB RAM
- 1GB free disk space
- Network interface with packet capture capabilities

### Recommended Requirements
- Python 3.9+
- 4GB RAM
- 5GB free disk space
- Dedicated network monitoring interface

## 🔒 Security Considerations

- Run with appropriate network permissions
- Secure Redis instance for production use
- Enable HTTPS for production deployment
- Regular security updates and monitoring
- Proper firewall configuration

## 📈 Performance Optimization

- Configure appropriate training times based on network size
- Adjust scanning intervals for optimal performance
- Monitor system resources during peak usage
- Use dedicated Redis instance for larger deployments

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Support

For support and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the system logs for error details

## 🔮 Future Enhancements

- Machine learning-based anomaly detection
- Advanced visualization and analytics
- Multi-network support
- Mobile application
- API integration capabilities
- Custom alert rule configuration
- Historical trend analysis
- Device vulnerability scanning
