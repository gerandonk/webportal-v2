const express = require('express');
const session = require('express-session');
const path = require('path');
const axios = require('axios');
const fs = require('fs');
require('dotenv').config();

// Fungsi untuk apa yah
function decodeToken(encoded) {
    return Buffer.from(encoded, 'base64').toString('utf-8');
}

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: 'rahasia-session',
    resave: false,
    saveUninitialized: true
}));

const PRO_STATUS_FILE = path.join(__dirname, 'pro-status.json');

// Initialize pro status file if it doesn't exist
if (!fs.existsSync(PRO_STATUS_FILE)) {
    fs.writeFileSync(PRO_STATUS_FILE, JSON.stringify({}));
}

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Routes
app.get('/', (req, res) => {
    res.render('login', { error: null });
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.get('/verify-otp', (req, res) => {
    // Redirect ke login jika tidak ada username
    if (!req.query.username) {
        return res.redirect('/login');
    }
    res.render('verify-otp', { username: req.query.username, error: null });
});

// Fungsi untuk generate OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000);
}

// Simpan OTP sementara (dalam praktik nyata sebaiknya gunakan database)
const otpStore = new Map();

// Load settings dari file
const SETTINGS_FILE = path.join(__dirname, 'settings.json');
let settings = {};

// Initialize settings file if it doesn't exist
if (!fs.existsSync(SETTINGS_FILE)) {
    settings = {
        otpEnabled: true,
        otpExpiry: 300,
        otpLength: 6,
        otpMessageTemplate: 'Kode OTP Anda untuk login WebPortal: {otp}. Kode ini berlaku selama {expiry} menit.'
    };
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2));
} else {
    settings = JSON.parse(fs.readFileSync(SETTINGS_FILE));
}

// Fungsi untuk generate OTP sesuai panjang yang diinginkan
function generateOTP() {
    const length = settings.otpLength || 6;
    const min = Math.pow(10, length - 1);
    const max = Math.pow(10, length) - 1;
    return Math.floor(min + Math.random() * (max - min + 1));
}

// Fungsi untuk format nomor WhatsApp
function formatWhatsAppNumber(number) {
    // Hapus semua spasi dan karakter non-digit
    number = number.replace(/\D/g, '');
    
    // Jika dimulai dengan 0, ganti dengan 62
    if (number.startsWith('0')) {
        number = '62' + number.slice(1);
    }
    // Jika dimulai dengan 62, biarkan apa adanya
    else if (number.startsWith('62')) {
        number = number;
    }
    // Jika tidak dimulai dengan 0 atau 62, tambahkan 62
    else {
        number = '62' + number;
    }
    
    return number;
}

// Fungsi untuk kirim OTP via WhatsApp Gateway
async function sendOTP(customerNumber, otp) {
    try {
        const formattedNumber = formatWhatsAppNumber(customerNumber);
        const expiryMinutes = Math.floor(settings.otpExpiry / 60);
        
        // Gunakan template pesan dari settings
        let message = settings.otpMessageTemplate || 'Kode OTP Anda untuk login WebPortal: {otp}. Kode ini berlaku selama {expiry} menit.';
        message = message.replace('{otp}', otp).replace('{expiry}', expiryMinutes);

        let response;
        
        switch(settings.waGateway) {
            case 'fonnte':
                if (!settings.fonnteApiKey) {
                    throw new Error('Fonnte API key tidak ditemukan');
                }
                response = await fetch('https://api.fonnte.com/send', {
                    method: 'POST',
                    headers: {
                        'Authorization': settings.fonnteApiKey,
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        target: formattedNumber,
                        message: message
                    })
                });
                break;

            case 'mpwa':
                if (!settings.mpwaApiKey || !settings.mpwaUrl) {
                    throw new Error('MPWA API key atau URL tidak ditemukan');
                }
                response = await fetch(`${settings.mpwaUrl}/send-message`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${settings.mpwaApiKey}`,
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        phone: formattedNumber,
                        message: message
                    })
                });
                break;

            case 'wablas':
                if (!settings.wablasApiKey || !settings.wablasUrl) {
                    throw new Error('Wablas API key atau URL tidak ditemukan');
                }
                response = await fetch(`${settings.wablasUrl}/api/send-message`, {
                    method: 'POST',
                    headers: {
                        'Authorization': settings.wablasApiKey,
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        phone: formattedNumber,
                        message: message
                    })
                });
                break;

            default:
                throw new Error('Gateway WhatsApp tidak valid');
        }

        if (!response.ok) {
            const errorData = await response.text();
            throw new Error(`Gagal mengirim OTP via ${settings.waGateway}: ${response.status} - ${errorData}`);
        }

        console.log(`OTP berhasil dikirim via ${settings.waGateway} ke ${formattedNumber}`);
        return true;

    } catch (error) {
        console.error('Error sending OTP:', error.message);
        return false;
    }
}

// Endpoint untuk login customer dengan OTP
app.post('/login', async (req, res) => {
    const { username } = req.body;
    if (!username) {
        return res.render('login', { error: 'Nomor pelanggan diperlukan' });
    }

    try {
        console.log('Attempting to connect to GenieACS server...');
        
        // Get all devices first
        const response = await axios.get(`${process.env.GENIEACS_URL}/devices`, {
            auth: {
                username: process.env.GENIEACS_USERNAME,
                password: process.env.GENIEACS_PASSWORD
            },
            headers: {
                'Accept': 'application/json'
            }
        });

        console.log('Total devices:', response.data.length);

        // Find device with matching tag
        const device = response.data.find(d => {
            console.log('Checking device:', {
                id: d._id,
                tags: d._tags,
                rawDevice: JSON.stringify(d)
            });
            return d._tags && d._tags.includes(username);
        });

        if (device) {
            console.log('Device found:', {
                deviceId: device._id,
                tags: device._tags
            });

            // Cek pengaturan OTP dari settings.json
            if (settings.otpEnabled) {
                // Generate dan kirim OTP
                const otp = generateOTP();
                const success = await sendOTP(username, otp);
                
                if (success) {
                    // Simpan OTP dengan waktu kadaluarsa sesuai settings
                    otpStore.set(username, {
                        code: otp,
                        expiry: Date.now() + (settings.otpExpiry * 1000)
                    });
                    // Redirect ke halaman verifikasi OTP
                    res.render('verify-otp', { username, error: null });
                } else {
                    res.render('login', { error: 'Gagal mengirim OTP, silakan coba lagi' });
                }
            } else {
                // Jika OTP dinonaktifkan, langsung login
                req.session.username = username;
                req.session.deviceId = device._id;
                res.redirect('/dashboard');
            }
        } else {
            console.log('No device found with tag:', username);
            res.render('login', { error: 'Nomor pelanggan tidak ditemukan' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.render('login', { error: 'Terjadi kesalahan saat login' });
    }
});

// Endpoint untuk menyimpan pengaturan OTP
app.post('/admin/settings/otp', async (req, res) => {
    if (!req.session.isAdmin) {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    try {
        const { otpEnabled, otpExpiry, otpLength, otpMessageTemplate } = req.body;

        // Validasi input
        if (typeof otpEnabled !== 'boolean' ||
            !Number.isInteger(otpExpiry) ||
            otpExpiry < 60 || otpExpiry > 3600 ||
            ![4, 6].includes(otpLength) ||
            !otpMessageTemplate) {
            return res.status(400).json({ 
                success: false, 
                message: 'Input tidak valid' 
            });
        }

        // Update settings
        settings = {
            ...settings,
            otpEnabled,
            otpExpiry,
            otpLength,
            otpMessageTemplate
        };

        // Simpan ke file
        fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2));

        res.json({ success: true });
    } catch (error) {
        console.error('Error saving OTP settings:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Gagal menyimpan pengaturan' 
        });
    }
});

// Update parameter paths untuk Product Class/Model
const parameterPaths = {
    pppUsername: [
        'VirtualParameters.pppoeUsername',
        'VirtualParameters.pppUsername',
        'InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username'
    ],
    rxPower: [
        'VirtualParameters.RXPower',
        'VirtualParameters.redaman',
        'InternetGatewayDevice.WANDevice.1.WANPONInterfaceConfig.RXPower'
    ],
    pppMac: [
        'VirtualParameters.pppMac',
        'VirtualParameters.WanMac',
        'InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.MACAddress',
        'InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.2.MACAddress',
        'InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress',
        'InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.2.MACAddress',
        'Device.IP.Interface.1.IPv4Address.1.IPAddress'
    ],
    pppMacWildcard: [
        'InternetGatewayDevice.WANDevice.*.WANConnectionDevice.1.WANPPPConnection.*.MACAddress',
        'InternetGatewayDevice.WANDevice.*.WANConnectionDevice.1.WANIPConnection.*.MACAddress'
    ],
    pppoeIP: [
        'VirtualParameters.pppoeIP',
        'VirtualParameters.pppIP'
    ],
    tr069IP: [
        'VirtualParameters.IPTR069'
    ],
    ssid: [
        'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID'
    ],
    ssid2G: [
        'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID'
    ],
    ssid5G: [
        'InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID'
    ],
    userConnected: [
        'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.TotalAssociations'
    ],
    userConnected2G: [
        'VirtualParameters.activedevices',
        'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.TotalAssociations',
        'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.AssociatedDeviceNumberOfEntries'
    ],
    userConnected5G: [
        'VirtualParameters.activedevices',
        'InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.TotalAssociations',
        'InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.AssociatedDeviceNumberOfEntries'
    ],
    uptime: [
        'VirtualParameters.getdeviceuptime'
    ],
    productClass: [
        'DeviceID.ProductClass',
        'InternetGatewayDevice.DeviceInfo.ProductClass',
        'Device.DeviceInfo.ProductClass',
        'InternetGatewayDevice.DeviceInfo.ModelName',
        'Device.DeviceInfo.ModelName'
    ],
    serialNumber: [
        'DeviceID.SerialNumber',
        'InternetGatewayDevice.DeviceInfo.SerialNumber',
        'Device.DeviceInfo.SerialNumber'
    ],
    registeredTime: [
        'Events.Registered'
    ]
};

// Update helper function untuk cek status device
const getDeviceStatus = (lastInform) => {
    const now = Date.now();
    const fiveMinutes = 5 * 60 * 1000; // 5 menit dalam milliseconds
    const lastInformTime = new Date(lastInform).getTime();
    
    return (now - lastInformTime) <= fiveMinutes;
};

// Dashboard route
app.get('/dashboard', async (req, res) => {
    if (!req.session.username || !req.session.deviceId) {
        return res.redirect('/');
    }

    try {
        const deviceResponse = await axios.get(`${process.env.GENIEACS_URL}/devices`, {
            params: {
                query: JSON.stringify({ "_id": req.session.deviceId })
            },
            auth: {
                username: process.env.GENIEACS_USERNAME,
                password: process.env.GENIEACS_PASSWORD
            }
        });

        if (!deviceResponse.data || !deviceResponse.data.length) {
            throw new Error('Device not found');
        }

        const device = deviceResponse.data[0];
        console.log('Raw device data:', JSON.stringify(device, null, 2));

        // Get device status
        const lastInform = device._lastInform;
        const deviceStatus = getDeviceStatus(lastInform);

        // Get Product Class/Model
        let model = getParameterWithPaths(device, parameterPaths.productClass);
        
        // Fallback ke device ID jika tidak ditemukan
        if (model === 'N/A') {
            const deviceIdParts = req.session.deviceId.split('-');
            if (deviceIdParts.length >= 2) {
                model = deviceIdParts[1];
            }
        }

        // Get Serial Number
        let serialNumber = getParameterWithPaths(device, parameterPaths.serialNumber);
        if (serialNumber === 'N/A') {
            const deviceIdParts = req.session.deviceId.split('-');
            if (deviceIdParts.length >= 3) {
                serialNumber = deviceIdParts[2];
            }
        }

        // Get device data
        const deviceData = {
            _id: device._id,
            _tags: device._tags || [],
            username: req.session.username,
            model: model,
            serialNumber: serialNumber,
            pppUsername: getParameterWithPaths(device, parameterPaths.pppUsername),
            pppMac: getParameterWithPaths(device, [...parameterPaths.pppMac, ...parameterPaths.pppMacWildcard]),
            pppoeIP: getParameterWithPaths(device, parameterPaths.pppoeIP),
            tr069IP: getParameterWithPaths(device, parameterPaths.tr069IP),
            ssid: getParameterWithPaths(device, parameterPaths.ssid),
            ssid2G: getParameterWithPaths(device, parameterPaths.ssid2G),
            ssid5G: getParameterWithPaths(device, parameterPaths.ssid5G),
            userConnected: getParameterWithPaths(device, parameterPaths.userConnected) || '0',
            userConnected2G: getParameterWithPaths(device, parameterPaths.userConnected2G) || '0',
            userConnected5G: getParameterWithPaths(device, parameterPaths.userConnected5G) || '0',
            rxPower: getParameterWithPaths(device, parameterPaths.rxPower),
            uptime: getParameterWithPaths(device, parameterPaths.uptime),
            registeredTime: getParameterWithPaths(device, parameterPaths.registeredTime),
            status: deviceStatus ? 'online' : 'offline',
            statusLabel: deviceStatus ? 'Online' : 'Offline',
            statusColor: deviceStatus ? '#33ff33' : '#ff0000',
            lastInform: new Date(lastInform || Date.now()).toLocaleString(),
            manufacturer: device.DeviceID?.Manufacturer || 'N/A'
        };

        // Clean up model name if needed
        deviceData.model = deviceData.model.replace('%2D', '-');

        console.log('Processed device data:', deviceData);

        res.render('dashboard', { deviceData, error: null });

    } catch (error) {
        console.error('Dashboard error:', error);
        res.render('dashboard', { 
            deviceData: {
                username: req.session.username,
                model: 'N/A',
                serialNumber: 'N/A',
                manufacturer: 'N/A',
                pppUsername: 'N/A',
                pppMac: 'N/A',
                pppoeIP: 'N/A',
                tr069IP: 'N/A',
                ssid: 'N/A',
                ssid2G: 'N/A',
                ssid5G: 'N/A',
                userConnected: '0',
                userConnected2G: '0',
                userConnected5G: '0',
                rxPower: 'N/A',
                uptime: 'N/A',
                registeredTime: 'N/A',
                status: 'unknown',
                statusLabel: 'Unknown',
                statusColor: '#99ccff',
                lastInform: 'N/A'
            },
            error: `Gagal mengambil data perangkat: ${error.message}`
        });
    }
});

// Helper function to format uptime
function formatUptime(seconds) {
    if (!seconds) return 'N/A';
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${days}d ${hours}h ${minutes}m`;
}

// Helper function to get nested value with multiple possible paths
const getParameterWithPaths = (device, paths) => {
    try {
        if (!device) {
            console.warn('Device object is null or undefined');
            return 'N/A';
        }

        for (const path of paths) {
            console.log(`Checking path: ${path}`);
            
            // Handle DeviceID special case
            if (path.startsWith('DeviceID.')) {
                const property = path.split('.')[1];
                if (device.DeviceID && device.DeviceID[property] !== undefined) {
                    const value = device.DeviceID[property];
                    console.log(`Found DeviceID value at ${path}:`, value);
                    // Clean up encoded characters if any
                    return typeof value === 'string' ? value.replace('%2D', '-') : value;
                }
            }
            
            // Handle wildcard paths
            if (path.includes('*')) {
                const parts = path.split('.');
                let current = device;
                let found = true;
                
                for (const part of parts) {
                    if (!current) {
                        found = false;
                        break;
                    }

                    if (part === '*') {
                        // Get all numeric keys
                        const keys = Object.keys(current || {}).filter(k => !isNaN(k));
                        // Try each key until we find a value
                        for (const key of keys) {
                            const temp = current[key];
                            if (temp?._value !== undefined) {
                                current = temp;
                                found = true;
                                break;
                            }
                            current = temp;
                        }
                        if (!current) {
                            found = false;
                            break;
                        }
                    } else {
                        current = current[part];
                    }
                }
                
                if (found && current?._value !== undefined) {
                    console.log(`Found value at ${path}:`, current._value);
                    return current._value;
                }
            } else {
                // Direct path
                const value = getNestedValue(device, path);
                if (value !== undefined) {
                    console.log(`Found value at ${path}:`, value);
                    return value;
                }
            }
        }

        console.log('No value found in any path');
        return 'N/A';
    } catch (error) {
        console.error(`Error getting value for path ${paths}:`, error);
        return 'N/A';
    }
};

// Function to safely get nested value
const getNestedValue = (obj, path) => {
    try {
        if (!obj || !path) return undefined;
        
        // Handle root level properties
        if (path.startsWith('_')) {
            return obj[path];
        }

        let current = obj;
        const parts = path.split('.');
        
        for (const part of parts) {
            if (!current) return undefined;
            current = current[part];
        }
        
        return current?._value;
    } catch (error) {
        console.error(`Error getting value for path ${path}:`, error);
        return undefined;
    }
};

// Helper function to encode device ID properly
function encodeDeviceId(deviceId) {
    // First decode to handle any existing encoding
    const decodedId = decodeURIComponent(deviceId);
    // Then encode properly for URL
    return encodeURIComponent(decodedId);
}

// Update SSID endpoint
app.post('/update-wifi', async (req, res) => {
    try {
        const { ssid2G, ssid5G, password2G, password5G, deviceId } = req.body;
        
        const parameterValues = [];
        
        if (ssid2G) {
            parameterValues.push(
                ["InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID", ssid2G, "xsd:string"]
            );
        }
        
        if (ssid5G) {
            parameterValues.push(
                ["InternetGatewayDevice.LANDevice.1.WLANConfiguration.2.SSID", ssid5G, "xsd:string"]
            );
        }

        if (password2G) {
            parameterValues.push(
                ["InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.KeyPassphrase", password2G, "xsd:string"],
                ["InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase", password2G, "xsd:string"]
            );
        }

        if (password5G) {
            parameterValues.push(
                ["InternetGatewayDevice.LANDevice.1.WLANConfiguration.2.PreSharedKey.1.KeyPassphrase", password5G, "xsd:string"],
                ["InternetGatewayDevice.LANDevice.1.WLANConfiguration.2.KeyPassphrase", password5G, "xsd:string"]
            );
        }

        // ... sisa kode update-wifi yang sudah ada ...
    } catch (error) {
        // ... error handling ...
    }
});

// Tambahkan helper function untuk RX Power class
const getRxPowerClass = (rxPower) => {
    if (!rxPower) return '';
    const power = parseFloat(rxPower);
    if (power > -25) return 'rx-power-good';
    if (power > -27) return 'rx-power-warning';
    return 'rx-power-critical';
};

// Update admin route
app.get('/admin', async (req, res) => {
    try {
        if (!req.session.isAdmin) {
            return res.redirect('/admin/login');
        }

        const response = await axios.get(`${process.env.GENIEACS_URL}/devices`, {
            auth: {
                username: process.env.GENIEACS_USERNAME,
                password: process.env.GENIEACS_PASSWORD
            }
        });

        const devices = response.data.map(device => {
            const activeDevices = getParameterWithPaths(device, ['VirtualParameters.activedevices']) || '0';
            // Asumsikan setengah dari total activedevices untuk masing-masing band
            const devicesPerBand = Math.ceil(parseInt(activeDevices) / 2);
            
            // Cek status berdasarkan last inform time
            const isOnline = getDeviceStatus(device._lastInform);
            
            // Get connected devices count
            const connectedDevices = getParameterWithPaths(device, [
                'InternetGatewayDevice.LANDevice.1.Hosts.HostNumberOfEntries',
                'Device.Hosts.HostNumberOfEntries'
            ]) || '0';

            return {
                _id: device._id,
                _tags: device._tags || [],
                online: isOnline,
                lastInform: device._lastInform || new Date(),
                pppUsername: getParameterWithPaths(device, parameterPaths.pppUsername) || 'Unknown',
                pppoeIP: getParameterWithPaths(device, parameterPaths.pppoeIP) || 'N/A',
                rxPower: getParameterWithPaths(device, parameterPaths.rxPower) || 'N/A',
                model: getParameterWithPaths(device, parameterPaths.productClass) || 'N/A',
                serialNumber: getParameterWithPaths(device, parameterPaths.serialNumber) || 'N/A',
                ssid: getParameterWithPaths(device, parameterPaths.ssid) || '',
                connectedDevices: connectedDevices,
                mac: getParameterWithPaths(device, [...parameterPaths.pppMac, ...parameterPaths.pppMacWildcard]) || 'N/A',
                userConnected2G: devicesPerBand.toString(),
                userConnected5G: devicesPerBand.toString(),
            };
        });

        res.render('admin', { 
            devices,
            getRxPowerClass,
            error: null
        });

    } catch (error) {
        console.error('Admin page error:', error);
        res.render('admin', { 
            devices: [],
            getRxPowerClass,
            error: 'Gagal memuat data perangkat: ' + error.message
        });
    }
});

// Admin login route
app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Cek kredensial admin
        if (username === process.env.ADMIN_USERNAME && 
            password === process.env.ADMIN_PASSWORD) {
            
            req.session.isAdmin = true;
            return res.redirect('/admin');
        }

        res.render('admin-login', { error: 'Username atau password admin salah' });

    } catch (error) {
        console.error('Admin login error:', error);
        res.render('admin-login', { error: 'Terjadi kesalahan saat login' });
    }
});

// Admin login page
app.get('/admin/login', (req, res) => {
    if (req.session.isAdmin) {
        return res.redirect('/admin');
    }
    res.render('admin-login', { error: null });
});

// Update logout to handle admin session
app.get('/logout', (req, res) => {
    if (req.session.isAdmin) {
        req.session.destroy();
        return res.redirect('/admin/login');
    }
    req.session.destroy();
    res.redirect('/');
});

// Add this endpoint to handle device refresh
app.post('/refresh-device', async (req, res) => {
    try {
        const deviceId = req.session.deviceId;
        
        if (!deviceId) {
            throw new Error('Device ID tidak valid');
        }

        const encodedDeviceId = encodeURIComponent(deviceId);
        console.log('Refreshing device:', encodedDeviceId);

        // Refresh all parameters
        await axios.post(
            `${process.env.GENIEACS_URL}/devices/${encodedDeviceId}/tasks?connection_request`,
            {
                name: "refreshObject",
                objectName: ""  // Empty string means refresh all parameters
            },
            {
                auth: {
                    username: process.env.GENIEACS_USERNAME,
                    password: process.env.GENIEACS_PASSWORD
                }
            }
        );

        // Wait for refresh to complete
        await new Promise(resolve => setTimeout(resolve, 3000));

        res.json({ 
            success: true, 
            message: 'Device berhasil di-refresh' 
        });

    } catch (error) {
        console.error('Refresh device error:', {
            message: error.message,
            status: error.response?.status,
            data: error.response?.data
        });
        
        res.status(500).json({ 
            success: false, 
            message: `Gagal me-refresh device: ${error.message}` 
        });
    }
});

// Refresh single device
app.post('/admin/refresh-device/:deviceId', async (req, res) => {
    try {
        if (!req.session.isAdmin) {
            return res.status(403).json({ success: false, message: 'Unauthorized' });
        }

        // Get original deviceId from GenieACS
        const originalDeviceId = req.params.deviceId
            .replace(/%252D/g, '-')  // Fix double encoding
            .replace(/%2D/g, '-')    // Fix single encoding
            .replace(/%20/g, ' ')    // Fix spaces
            .replace(/\+/g, ' ');    // Fix plus signs

        console.log('Request deviceId:', req.params.deviceId);
        console.log('Processed deviceId:', originalDeviceId);

        // Construct GenieACS URLs
        const baseUrl = process.env.GENIEACS_URL.replace(/\/$/, ''); // Remove trailing slash if exists
        const refreshUrl = `${baseUrl}/devices/${originalDeviceId}/tasks?connection_request`;

        console.log('Refresh URL:', refreshUrl);

        // Verify device exists first
        try {
            const deviceCheck = await axios.get(`${baseUrl}/devices/${originalDeviceId}`, {
                auth: {
                    username: process.env.GENIEACS_USERNAME,
                    password: process.env.GENIEACS_PASSWORD
                }
            });

            if (!deviceCheck.data) {
                throw new Error('Device not found in GenieACS');
            }

            console.log('Device found in GenieACS');

            // Encode device ID properly for URL
            const encodedDeviceId = encodeURIComponent(originalDeviceId);
            console.log('Encoded deviceId:', encodedDeviceId);

            // Send refresh task
            const taskResponse = await axios({
                method: 'POST',
                url: `${baseUrl}/devices/${encodedDeviceId}/tasks`,
                data: {
                    name: "setParameterValues",
                    parameterValues: [["InternetGatewayDevice.ManagementServer.PeriodicInformEnable", "1", "xsd:boolean"]]
                },
                auth: {
                    username: process.env.GENIEACS_USERNAME,
                    password: process.env.GENIEACS_PASSWORD
                },
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            console.log('Task response:', {
                status: taskResponse.status,
                data: taskResponse.data,
                url: taskResponse.config.url
            });

            // Wait for tasks to be processed
            await new Promise(resolve => setTimeout(resolve, 3000));

            res.json({ 
                success: true, 
                message: 'Device refreshed successfully',
                deviceId: originalDeviceId
            });

        } catch (axiosError) {
            console.error('GenieACS API error:', {
                url: axiosError.config?.url,
                status: axiosError.response?.status,
                data: axiosError.response?.data,
                message: axiosError.message
            });
            
            let errorMessage = 'GenieACS API error';
            if (axiosError.response?.status === 404) {
                errorMessage = 'Device not found in GenieACS';
            } else if (axiosError.response?.data?.message) {
                errorMessage = axiosError.response.data.message;
            } else {
                errorMessage = axiosError.message;
            }

            throw new Error(errorMessage);
        }

    } catch (error) {
        console.error('Refresh device error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to refresh device: ' + error.message,
            deviceId: req.params.deviceId,
            error: error.message
        });
    }
});

// Refresh all devices
app.post('/admin/refresh-all', async (req, res) => {
    try {
        if (!req.session.isAdmin) {
            return res.status(403).json({ success: false, message: 'Unauthorized' });
        }

        // Ambil semua devices
        const response = await axios.get(`${process.env.GENIEACS_URL}/devices`, {
            auth: {
                username: process.env.GENIEACS_USERNAME,
                password: process.env.GENIEACS_PASSWORD
            }
        });

        const refreshPromises = response.data.map(async (device) => {
            try {
                // Encode device ID properly for URL
                const encodedDeviceId = encodeURIComponent(device._id);
                console.log('Processing device:', {
                    original: device._id,
                    encoded: encodedDeviceId
                });

                // Send refresh task
                const result = await axios({
                    method: 'POST',
                    url: `${process.env.GENIEACS_URL}/devices/${encodedDeviceId}/tasks`,
                    data: {
                        name: "setParameterValues",
                        parameterValues: [["InternetGatewayDevice.ManagementServer.PeriodicInformEnable", "1", "xsd:boolean"]]
                    },
                    auth: {
                        username: process.env.GENIEACS_USERNAME,
                        password: process.env.GENIEACS_PASSWORD
                    },
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });

                console.log('Device refresh result:', {
                    deviceId: device._id,
                    status: result.status,
                    data: result.data,
                    url: result.config.url
                });

                return { deviceId: device._id, success: true };
            } catch (error) {
                console.warn(`Failed to refresh device ${device._id}:`, error.message);
                return { deviceId: device._id, success: false, error: error.message };
            }
        });

        // Tunggu semua refresh selesai
        const results = await Promise.allSettled(refreshPromises);

        // Hitung statistik
        const successful = results.filter(r => r.status === 'fulfilled' && r.value.success).length;
        const failed = results.filter(r => r.status === 'rejected' || !r.value.success).length;

        res.json({ 
            success: true, 
            message: `Refresh completed. Success: ${successful}, Failed: ${failed}`,
            details: results.map(r => r.value || r.reason)
        });

    } catch (error) {
        console.error('Refresh all devices error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to refresh devices: ' + error.message 
        });
    }
});

// Ganti dengan fungsi enkripsi yang lebih aman
function encryptToken(text) {
    const crypto = require('crypto');
    const algorithm = 'aes-256-ctr';
    const secretKey = process.env.SECRET_KEY || 'default-secret-key-12345';
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);

    return {
        iv: iv.toString('hex'),
        content: encrypted.toString('hex')
    };
}

function decryptToken(hash) {
    const crypto = require('crypto');
    const algorithm = 'aes-256-ctr';
    const secretKey = process.env.SECRET_KEY || 'default-secret-key-12345';
    const iv = Buffer.from(hash.iv, 'hex');
    const content = Buffer.from(hash.content, 'hex');

    const decipher = crypto.createDecipheriv(algorithm, secretKey, iv);
    const decrypted = Buffer.concat([decipher.update(content), decipher.final()]);

    return decrypted.toString();
}

// Update endpoint untuk verifikasi token
app.post('/set-pro-status', (req, res) => {
    const { token } = req.body;
    if (token === getValidToken()) {
        const proStatus = JSON.parse(fs.readFileSync(PRO_STATUS_FILE));
        proStatus.isPro = true;
        fs.writeFileSync(PRO_STATUS_FILE, JSON.stringify(proStatus));
        res.json({ success: true });
    } else {
        res.status(400).json({ success: false });
    }
});

// Endpoint untuk memeriksa status PRO
app.get('/check-pro-status', (req, res) => {
    const proStatus = JSON.parse(fs.readFileSync(PRO_STATUS_FILE));
    res.json({ isPro: proStatus.isPro || false });
});

// Endpoint untuk reboot device
app.post('/reboot-device', async (req, res) => {
    const { deviceId } = req.body;
    
    try {
        // Log reboot attempt
        console.log('Attempting to reboot device:', deviceId);
        
        const response = await axios.post(
            `${process.env.GENIEACS_URL}/devices/${encodeURIComponent(deviceId)}/tasks?timeout=3000&connection_request`,
            { name: "reboot" },
            {
                auth: {
                    username: process.env.GENIEACS_USERNAME,
                    password: process.env.GENIEACS_PASSWORD
                },
                headers: {
                    'Content-Type': 'application/json'
                }
            }
        );

        console.log('Reboot response:', response.data);
        res.json({ success: true, message: 'Perintah reboot berhasil dikirim' });
    } catch (error) {
        console.error('Reboot error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Gagal mengirim perintah reboot',
            error: error.message 
        });
    }
});

// Update customer number
app.post('/update-customer-number', async (req, res) => {
    try {
        const { deviceId, customerNumber } = req.body;
        
        if (!deviceId || !customerNumber) {
            return res.status(400).json({ 
                success: false, 
                message: 'Device ID dan nomor pelanggan harus diisi' 
            });
        }

        // Validate customer number format
        if (!/^\d+$/.test(customerNumber)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Nomor pelanggan harus berupa angka' 
            });
        }

        // Encode device ID properly for the query
        const encodedQuery = encodeURIComponent(JSON.stringify({ "_id": deviceId }));
        console.log('Searching device with query:', encodedQuery);

        // Get current tags using GenieACS query API
        const response = await axios.get(`${process.env.GENIEACS_URL}/devices/?query=${encodedQuery}`, {
            auth: {
                username: process.env.GENIEACS_USERNAME,
                password: process.env.GENIEACS_PASSWORD
            }
        });

        console.log('GenieACS response:', response.data);

        if (!response.data || !response.data.length) {
            return res.status(404).json({
                success: false,
                message: 'Device tidak ditemukan'
            });
        }

        const device = response.data[0];
        const currentTags = device._tags || [];
        console.log('Current tags:', currentTags);

        // Remove existing numeric tags
        for (const tag of currentTags) {
            if (/^\d+$/.test(tag)) {
                console.log('Removing tag:', tag);
                await axios.delete(`${process.env.GENIEACS_URL}/devices/${encodeURIComponent(deviceId)}/tags/${tag}`, {
                    auth: {
                        username: process.env.GENIEACS_USERNAME,
                        password: process.env.GENIEACS_PASSWORD
                    }
                });
            }
        }

        // Add new customer number tag
        console.log('Adding new tag:', customerNumber);
        await axios.post(`${process.env.GENIEACS_URL}/devices/${encodeURIComponent(deviceId)}/tags/${customerNumber}`, null, {
            auth: {
                username: process.env.GENIEACS_USERNAME,
                password: process.env.GENIEACS_PASSWORD
            }
        });

        res.json({ 
            success: true, 
            message: 'Nomor pelanggan berhasil diupdate' 
        });

    } catch (error) {
        console.error('Error updating customer number:', error);
        console.error('Error details:', {
            message: error.message,
            response: error.response?.data,
            status: error.response?.status
        });
        res.status(500).json({ 
            success: false, 
            message: 'Terjadi kesalahan saat mengupdate nomor pelanggan: ' + error.message 
        });
    }
});

// Pastikan route ini berada sebelum route lainnya dan setelah middleware session
app.get('/admin/settings', async (req, res) => {
    // Cek session admin
    if (!req.session.isAdmin) {
        return res.redirect('/login');
    }

    try {
        let settings = {};
        const settingsFile = path.join(__dirname, 'settings.json');

        // Cek apakah file settings.json sudah ada
        if (fs.existsSync(settingsFile)) {
            settings = JSON.parse(fs.readFileSync(settingsFile, 'utf8'));
        } else {
            // Default settings jika file belum ada
            settings = {
                otpEnabled: true,
                waGateway: 'fonnte',
                adminWhatsapp: '',
                fonnteApiKey: '',
                mpwaUrl: '',
                mpwaApiKey: '',
                wablasUrl: '',
                wablasApiKey: ''
            };
            // Buat file settings.json dengan default settings
            fs.writeFileSync(settingsFile, JSON.stringify(settings, null, 2));
        }

        res.render('settings', { settings });
    } catch (error) {
        console.error('Settings page error:', error);
        res.status(500).send('Error loading settings: ' + error.message);
    }
});

// Save settings endpoint
app.post('/admin/settings', async (req, res) => {
    if (!req.session.isAdmin) {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    try {
        const settings = {
            otpEnabled: Boolean(req.body.otpEnabled),
            waGateway: req.body.waGateway,
            adminWhatsapp: req.body.adminWhatsapp,
            fonnteApiKey: req.body.fonnteApiKey,
            mpwaUrl: req.body.mpwaUrl,
            mpwaApiKey: req.body.mpwaApiKey,
            wablasUrl: req.body.wablasUrl,
            wablasApiKey: req.body.wablasApiKey
        };

        const settingsFile = path.join(__dirname, 'settings.json');
        fs.writeFileSync(settingsFile, JSON.stringify(settings, null, 2));

        res.json({ success: true, message: 'Settings saved successfully' });
    } catch (error) {
        console.error('Save settings error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to save settings: ' + error.message 
        });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server berjalan di port ${PORT}`);
});

function getValidToken() {
    const parts = [
        Buffer.from('YWxp', 'base64').toString(),  // 'ali'
        Buffer.from('amF5YQ==', 'base64').toString(), // 'jaya'
        Buffer.from('bmV0', 'base64').toString()   // 'net'
    ];
    return parts.join('');
}