const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');

// Load environment variables
dotenv.config();

const app = express();

// CORS Configuration for Production
const corsOptions = {
    origin: function(origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
            'https://www.kyroshield.com',      // Your GoDaddy domain (with www)
            'https://kyroshield.com',          // Your GoDaddy domain (without www)
            'http://localhost:5500',           // Live Server default port
            'http://127.0.0.1:5500',           // Live Server alternative
            'http://localhost:5501',           // Your settings.json port
            'http://127.0.0.1:5501',           // Alternative
            'http://localhost:3000',           // For testing backend directly
            process.env.NODE_ENV === 'development' && origin  // Allow all in dev
        ].filter(Boolean); // Remove false values
        
        if (allowedOrigins.includes(origin) || process.env.NODE_ENV === 'development') {
            return callback(null, true);
        } else {
            console.log('CORS blocked origin:', origin);
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: {
        success: false,
        message: 'Too many requests from this IP, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

app.use('/api/send-email', limiter);

// Configure Nodemailer transporter
const createTransporter = () => {
    try {
        if (!process.env.EMAIL_HOST || !process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
            throw new Error('Missing email configuration. Check your .env file.');
        }

        const transporter = nodemailer.createTransport({
            host: process.env.EMAIL_HOST,
            port: parseInt(process.env.EMAIL_PORT) || 587,
            secure: process.env.EMAIL_SECURE === 'true',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD
            },
            tls: {
                rejectUnauthorized: false
            }
        });

        return transporter;
    } catch (error) {
        console.error('❌ Failed to create email transporter:', error.message);
        return null;
    }
};

// Health check endpoint
app.get('/api/health', (req, res) => {
    const transporter = createTransporter();
    const emailConfigOk = transporter !== null;
    
    res.json({
        success: true,
        message: 'Kyroshield Backend Server',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        email: {
            configured: emailConfigOk,
            host: process.env.EMAIL_HOST ? 'Configured' : 'Not configured'
        }
    });
});

// Test email endpoint
app.post('/api/test-email', async (req, res) => {
    try {
        const { testEmail } = req.body;
        
        if (!testEmail) {
            return res.status(400).json({
                success: false,
                message: 'Test email address is required'
            });
        }

        const transporter = createTransporter();
        
        if (!transporter) {
            return res.status(500).json({
                success: false,
                message: 'Email transporter not configured. Check your .env file.'
            });
        }

        const testMailOptions = {
            from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
            to: testEmail,
            subject: 'Test Email from Kyroshield Server',
            text: `This is a test email sent from your Kyroshield server at ${new Date().toLocaleString()}`,
            html: `<p>This is a test email sent from your <strong>Kyroshield</strong> server.</p>
                   <p>Timestamp: ${new Date().toLocaleString()}</p>
                   <p>If you received this, your email configuration is working correctly!</p>`
        };

        await transporter.sendMail(testMailOptions);
        
        console.log(`✅ Test email sent to ${testEmail}`);
        
        res.status(200).json({
            success: true,
            message: `Test email sent successfully to ${testEmail}`
        });

    } catch (error) {
        console.error('❌ Test email error:', error);
        
        let errorMessage = 'Failed to send test email. ';
        
        if (error.code === 'EAUTH') {
            errorMessage += 'Authentication failed. Check your email credentials in Railway variables.';
        } else {
            errorMessage += error.message;
        }

        res.status(500).json({
            success: false,
            message: errorMessage
        });
    }
});

// Email sending endpoint (for quote form)
app.post('/api/send-email', async (req, res) => {
    try {
        const { name, company, email, phone, service, message } = req.body;

        // Log incoming request
        console.log('📨 New quote request:', { name, company, email, service });

        // Validation
        if (!name || !company || !email || !phone || !service) {
            return res.status(400).json({
                success: false,
                message: 'Please fill in all required fields.'
            });
        }

        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                message: 'Please enter a valid email address.'
            });
        }

        const transporter = createTransporter();
        
        if (!transporter) {
            return res.status(500).json({
                success: false,
                message: 'Email service is currently unavailable. Please try again later.'
            });
        }

        // Format service name for display
        const serviceNames = {
            'data-destruction': 'Certified Data Destruction',
            'itad': 'IT Asset Disposition (ITAD)',
            'e-waste': 'E-waste Recycling & Compliance',
            'multiple': 'Multiple Services',
            'other': 'Other'
        };

        const serviceDisplayName = serviceNames[service] || service;

        // Email content for Kyroshield (admin)
        const adminMailOptions = {
            from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
            to: process.env.EMAIL_TO || process.env.EMAIL_USER,
            subject: `New Quote Request: ${name} from ${company}`,
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background-color: #000; color: white; padding: 20px; text-align: center; }
                        .content { background-color: #f9f9f9; padding: 30px; border-radius: 8px; }
                        .field { margin-bottom: 15px; }
                        .label { font-weight: bold; color: #000; }
                        .value { color: #666; }
                        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #777; font-size: 12px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h2>📋 New Quote Request</h2>
                            <p>Kyroshield Website Form Submission</p>
                        </div>
                        <div class="content">
                            <div class="field">
                                <div class="label">Full Name:</div>
                                <div class="value">${name}</div>
                            </div>
                            <div class="field">
                                <div class="label">Company:</div>
                                <div class="value">${company}</div>
                            </div>
                            <div class="field">
                                <div class="label">Email:</div>
                                <div class="value">${email}</div>
                            </div>
                            <div class="field">
                                <div class="label">Phone:</div>
                                <div class="value">${phone}</div>
                            </div>
                            <div class="field">
                                <div class="label">Service Interested In:</div>
                                <div class="value">${serviceDisplayName}</div>
                            </div>
                            <div class="field">
                                <div class="label">Additional Details:</div>
                                <div class="value">${message || 'No additional details provided.'}</div>
                            </div>
                        </div>
                        <div class="footer">
                            <p>This email was automatically generated from the Kyroshield website contact form.</p>
                            <p>Timestamp: ${new Date().toLocaleString()}</p>
                        </div>
                    </div>
                </body>
                </html>
            `
        };

        // Email content for the customer (confirmation)
        const customerMailOptions = {
            from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
            to: email,
            subject: 'Thank You for Your Quote Request - Kyroshield',
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: 'Inter', Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background-color: #000; color: white; padding: 30px; text-align: center; }
                        .logo { font-family: 'Montserrat', sans-serif; font-size: 24px; font-weight: bold; }
                        .logo-accent { color: #999; }
                        .content { background-color: #f8f9fa; padding: 30px; border-radius: 8px; margin: 20px 0; }
                        .thank-you { color: #000; font-size: 20px; margin-bottom: 20px; }
                        .details { background-color: white; padding: 20px; border-radius: 4px; border-left: 4px solid #000; }
                        .next-steps { margin-top: 30px; padding: 20px; background-color: #e9ecef; border-radius: 4px; }
                        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #666; font-size: 14px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <div class="logo">KYRO<span class="logo-accent">SHIELD</span></div>
                            <p>Secure. Comply. Evolve.</p>
                        </div>
                        
                        <div class="content">
                            <h2 class="thank-you">Thank You for Contacting Kyroshield!</h2>
                            
                            <p>Dear ${name},</p>
                            
                            <p>We have received your request for a quote regarding <strong>${serviceDisplayName}</strong> services. Our team will review your inquiry and contact you within 24 business hours.</p>
                            
                            <div class="details">
                                <h3>Your Request Details:</h3>
                                <p><strong>Name:</strong> ${name}</p>
                                <p><strong>Company:</strong> ${company}</p>
                                <p><strong>Service:</strong> ${serviceDisplayName}</p>
                                <p><strong>Submitted:</strong> ${new Date().toLocaleString()}</p>
                            </div>
                            
                            <div class="next-steps">
                                <h3>What Happens Next:</h3>
                                <ol>
                                    <li>Our team will review your requirements</li>
                                    <li>We'll prepare a customized quote based on your needs</li>
                                    <li>A specialist will contact you to discuss the details</li>
                                    <li>We'll provide a comprehensive service proposal</li>
                                </ol>
                            </div>
                            
                            <p>If you have any urgent questions, feel free to contact us directly at <strong>+60 013-456 6146</strong>.</p>
                            
                            <p>Best regards,<br>
                            <strong>The Kyroshield Team</strong></p>
                        </div>
                        
                        <div class="footer">
                            <p><strong>Kyroshield Headquarters</strong><br>
                            Johor Bahru, Malaysia<br>
                            Phone: +60 013-456 6146<br>
                            Email: contact@kyroshield.com</p>
                            
                            <p>Business Hours: Monday - Friday, 9:00 AM - 6:00 PM</p>
                            
                            <p style="font-size: 12px; color: #999; margin-top: 20px;">
                                This is an automated message. Please do not reply to this email.
                            </p>
                        </div>
                    </div>
                </body>
                </html>
            `
        };

        // Send both emails
        const adminResult = await transporter.sendMail(adminMailOptions);
        const customerResult = await transporter.sendMail(customerMailOptions);

        console.log(`✅ Email sent successfully`);
        console.log(`   Admin email: ${adminResult.messageId}`);
        console.log(`   Customer email: ${customerResult.messageId} to ${email}`);

        res.status(200).json({
            success: true,
            message: 'Thank you for your request! We have sent a confirmation email and will contact you within 24 hours.'
        });

    } catch (error) {
        console.error('❌ Email sending error:', error);
        
        let errorMessage = 'Failed to send email. Please try again later.';
        
        if (error.code === 'EAUTH') {
            errorMessage = 'Email authentication failed. Please check your email configuration.';
        }

        res.status(500).json({
            success: false,
            message: errorMessage
        });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        success: false,
        message: 'Something went wrong!',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Endpoint not found'
    });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📧 Email service ready`);
    
    // Use Railway URL if available, otherwise localhost
    const railwayUrl = process.env.RAILWAY_STATIC_URL || `http://localhost:${PORT}`;
    console.log(`🌐 Health check: ${railwayUrl}/api/health`);
    console.log(`📝 Quote endpoint: POST ${railwayUrl}/api/send-email`);
});