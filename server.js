const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const sgMail = require('@sendgrid/mail'); // Changed from nodemailer to SendGrid
const rateLimit = require('express-rate-limit');

// Load environment variables
dotenv.config();

// Initialize SendGrid
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const app = express();

// Trust Railway's proxy for rate limiting
app.set('trust proxy', 1);

// Add request logging middleware FIRST
app.use((req, res, next) => {
    console.log('\n=== NEW REQUEST ===');
    console.log(`Time: ${new Date().toISOString()}`);
    console.log(`Method: ${req.method}`);
    console.log(`Path: ${req.path}`);
    console.log(`Origin Header: ${req.headers.origin || 'No origin header'}`);
    console.log(`Referer: ${req.headers.referer || 'No referer'}`);
    next();
});

// CORS Configuration - FIXED VERSION
const corsOptions = {
    origin: function(origin, callback) {
        // Allow requests with no origin (like mobile apps, curl, or same-origin requests)
        if (!origin) {
            console.log('📡 No origin header - allowing request');
            return callback(null, true);
        }
        
        console.log('🔍 Checking CORS for origin:', origin);
        
        // Normalize origin by removing trailing slash
        const normalizedOrigin = origin.replace(/\/$/, '').toLowerCase();
        
        const allowedOrigins = [
            'https://www.kyroshield.com',
            'https://kyroshield.com',
            'http://localhost:5501',
            'http://127.0.0.1:5501',
            'https://kyroshield-backend.up.railway.app',
            'https://cloudflare.com',  // Add Cloudflare
            'https://www.cloudflare.com'  // Add Cloudflare www
        ].map(url => url.replace(/\/$/, '').toLowerCase());
        
        console.log('📋 Allowed origins (normalized):', allowedOrigins);
        
        // Allow all origins in development
        if (process.env.NODE_ENV === 'development') {
            console.log('⚙️ Development mode - allowing all origins');
            return callback(null, true);
        }
        
        // Check exact match
        if (allowedOrigins.includes(normalizedOrigin)) {
            console.log('✅ CORS allowed - exact match');
            return callback(null, true);
        }
        
        // Check for variations (www vs non-www)
        if (normalizedOrigin === 'https://www.kyroshield.com' || 
            normalizedOrigin === 'https://kyroshield.com') {
            console.log('✅ CORS allowed - kyroshield.com variation');
            return callback(null, true);
        }
        
        // Check for localhost variations
        if (normalizedOrigin.includes('localhost:5501') || 
            normalizedOrigin.includes('127.0.0.1:5501')) {
            console.log('✅ CORS allowed - localhost variation');
            return callback(null, true);
        }
        
        // Check for railway variations
        if (normalizedOrigin.includes('railway.app')) {
            console.log('✅ CORS allowed - railway.app domain');
            return callback(null, true);
        }
        
        console.log('❌ CORS blocked - origin not in allowed list:', normalizedOrigin);
        // TEMPORARY: Allow all origins for testing
        return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400 // 24 hours for preflight cache
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Handle pre-flight for all routes

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
    skip: (req) => {
        // Skip rate limiting for OPTIONS requests (pre-flight)
        return req.method === 'OPTIONS';
    }
});

app.use('/api/send-email', limiter);

// SendGrid email helper function
const sendEmail = async (to, subject, html, text = null) => {
    try {
        const msg = {
            to,
            from: process.env.EMAIL_FROM || 'contact@kyroshield.com',
            subject,
            html,
            text: text || html.replace(/<[^>]*>/g, '') // Convert HTML to text
        };
        
        console.log(`📤 Sending email to ${to} via SendGrid API`);
        const result = await sgMail.send(msg);
        console.log(`✅ Email sent via SendGrid: ${result[0].headers['x-message-id']}`);
        return { success: true, messageId: result[0].headers['x-message-id'] };
    } catch (error) {
        console.error('❌ SendGrid error:', error);
        throw error;
    }
};

// Health check endpoint with CORS headers
app.get('/api/health', (req, res) => {
    const emailConfigured = !!process.env.SENDGRID_API_KEY;
    
    const healthData = {
        success: true,
        message: 'Kyroshield Backend Server',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        nodeVersion: process.version,
        uptime: process.uptime(),
        email: {
            configured: emailConfigured,
            service: 'SendGrid API',
            from: process.env.EMAIL_FROM || 'Not configured'
        },
        request: {
            origin: req.headers.origin || 'No origin header',
            ip: req.ip,
            method: req.method,
            url: req.url
        }
    };
    
    console.log('🏥 Health check requested:', healthData.request);
    res.json(healthData);
});

// SendGrid test endpoint
app.get('/api/test-sendgrid', async (req, res) => {
    try {
        console.log('🔧 Testing SendGrid connection...');
        
        if (!process.env.SENDGRID_API_KEY) {
            return res.status(500).json({
                success: false,
                message: 'SendGrid API key not configured.'
            });
        }
        
        // Test by sending a simple request to SendGrid
        await sgMail.send({
            to: 'test@example.com',
            from: process.env.EMAIL_FROM || 'test@kyroshield.com',
            subject: 'SendGrid Test',
            text: 'Testing SendGrid connection',
            html: '<p>Testing SendGrid connection</p>'
        });
        
        console.log('✅ SendGrid connection verified');
        
        res.json({
            success: true,
            message: 'SendGrid connection successful',
            config: {
                service: 'SendGrid API',
                from: process.env.EMAIL_FROM || 'Not configured',
                apiKeyConfigured: !!process.env.SENDGRID_API_KEY
            }
        });
        
    } catch (error) {
        console.error('❌ SendGrid test error:', error);
        
        let errorMessage = 'SendGrid connection failed. ';
        
        if (error.response && error.response.body && error.response.body.errors) {
            errorMessage += error.response.body.errors.map(err => err.message).join(', ');
        } else {
            errorMessage += error.message;
        }
        
        res.status(500).json({
            success: false,
            message: errorMessage
        });
    }
});

// CORS test endpoint
app.get('/api/cors-test', (req, res) => {
    res.json({
        success: true,
        message: 'CORS test endpoint',
        origin: req.headers.origin || 'No origin header',
        method: req.method,
        timestamp: new Date().toISOString()
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

        if (!process.env.SENDGRID_API_KEY) {
            return res.status(500).json({
                success: false,
                message: 'SendGrid API key not configured.'
            });
        }

        const html = `<p>This is a test email sent from your <strong>Kyroshield</strong> server via SendGrid API.</p>
                      <p>Timestamp: ${new Date().toLocaleString()}</p>
                      <p>If you received this, your SendGrid configuration is working correctly!</p>`;

        await sendEmail(testEmail, 'Test Email from Kyroshield Server', html);
        
        res.status(200).json({
            success: true,
            message: `Test email sent successfully to ${testEmail} via SendGrid API`
        });

    } catch (error) {
        console.error('❌ Test email error:', error);
        
        let errorMessage = 'Failed to send test email. ';
        
        if (error.response && error.response.body && error.response.body.errors) {
            errorMessage += error.response.body.errors.map(err => err.message).join(', ');
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

        if (!process.env.SENDGRID_API_KEY) {
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

        // Admin email HTML
        const adminHtml = `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background-color: #000; color: white; padding: 30px 20px; text-align: center; }
                .text-logo { 
                    font-family: 'Montserrat', Arial, sans-serif; 
                    font-size: 36px; 
                    font-weight: bold; 
                    color: white; 
                    margin-bottom: 10px; 
                    letter-spacing: 1px; 
                }
                .logo-accent { color: #999; }
                .tagline { color: #ccc; font-size: 14px; letter-spacing: 1px; margin: 0; }
                .content { background-color: #f9f9f9; padding: 30px; border-radius: 8px; }
                .field { margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px solid #eee; }
                .label { font-weight: bold; color: #000; margin-bottom: 5px; }
                .value { color: #666; line-height: 1.4; }
                .message-box { background-color: #fff8e1; padding: 20px; border-radius: 4px; margin: 20px 0; }
                .action-buttons { margin-top: 25px; text-align: center; }
                .btn { display: inline-block; padding: 12px 24px; margin: 0 10px; background-color: #000; color: white; text-decoration: none; border-radius: 4px; }
                .btn:hover { background-color: #333; }
                .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #777; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="text-logo">KYRO<span class="logo-accent">SHIELD</span></div>
                    <p class="tagline">Secure. Comply. Evolve.</p>
                    <h2 style="margin: 20px 0 0 0; font-size: 20px;">📋 New Quote Request</h2>
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
                        <div class="value"><a href="mailto:${email}">${email}</a></div>
                    </div>
                    <div class="field">
                        <div class="label">Phone:</div>
                        <div class="value"><a href="tel:${phone}">${phone}</a></div>
                    </div>
                    <div class="field">
                        <div class="label">Service Interested In:</div>
                        <div class="value"><strong>${serviceDisplayName}</strong></div>
                    </div>
                    
                    ${message ? `
                    <div class="message-box">
                        <div class="label">📝 Additional Details:</div>
                        <div class="value">${message}</div>
                    </div>
                    ` : '<div class="field"><div class="label">📝 Additional Details:</div><div class="value"><em>No additional details provided.</em></div></div>'}
                    
                    <div class="field">
                        <div class="label">Timestamp:</div>
                        <div class="value">${new Date().toLocaleString('en-MY', { timeZone: 'Asia/Kuala_Lumpur' })}</div>
                    </div>
                    
                    <div class="action-buttons">
                        <a href="mailto:${email}?subject=Re: Quote Request for ${serviceDisplayName}&body=Dear ${name},%0D%0A%0D%0AThank you for your inquiry about our ${serviceDisplayName} services.%0D%0A%0D%0AWe would like to discuss your requirements further.%0D%0A%0D%0ABest regards,%0D%0AThe Kyroshield Team" class="btn">
                            📧 Reply to ${name}
                        </a>
                        <a href="https://www.kyroshield.com/admin" class="btn">
                            📊 View in Dashboard
                        </a>
                    </div>
                </div>
                <div class="footer">
                    <p>This email was automatically generated from the Kyroshield website contact form.</p>
                    <p>Lead ID: ${Date.now()}-${Math.random().toString(36).substr(2, 9)}</p>
                </div>
            </div>
        </body>
        </html>
        `;

        // Customer email HTML
        const customerHtml = `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { 
                    font-family: 'Inter', 'Segoe UI', Arial, sans-serif; 
                    line-height: 1.6; 
                    color: #333333; 
                    margin: 0; 
                    padding: 0; 
                    background-color: #f8f9fa; 
                }
                .container { 
                    max-width: 600px; 
                    margin: 0 auto; 
                    background-color: #ffffff; 
                }
                .header { 
                    background-color: #000000; 
                    padding: 30px 20px; 
                    text-align: center; 
                }
                .text-logo { 
                    font-family: 'Montserrat', Arial, sans-serif; 
                    font-size: 32px; 
                    font-weight: bold; 
                    color: white; 
                    margin-bottom: 10px; 
                    letter-spacing: 1px; 
                }
                .logo-accent { 
                    color: #999999; 
                }
                .tagline { 
                    color: #cccccc; 
                    font-size: 14px; 
                    letter-spacing: 1px; 
                    margin: 0; 
                    text-transform: uppercase; 
                }
                .content { 
                    padding: 40px 30px; 
                }
                .thank-you { 
                    color: #000000; 
                    font-size: 24px; 
                    font-weight: 600; 
                    margin-bottom: 25px; 
                    text-align: center; 
                }
                .greeting { 
                    font-size: 16px; 
                    margin-bottom: 25px; 
                    color: #555555; 
                }
                .details-container { 
                    background-color: #f8f9fa; 
                    padding: 25px; 
                    border-radius: 8px; 
                    border-left: 4px solid #000000; 
                    margin: 25px 0; 
                }
                .details-title { 
                    font-size: 18px; 
                    font-weight: 600; 
                    margin-bottom: 20px; 
                    color: #000000; 
                }
                .detail-item { 
                    margin-bottom: 12px; 
                    display: flex; 
                }
                .detail-label { 
                    font-weight: 600; 
                    color: #000000; 
                    min-width: 140px; 
                }
                .detail-value { 
                    color: #555555; 
                    flex: 1; 
                }
                .message-box { 
                    background-color: #fff3cd; 
                    border: 1px solid #ffeaa7; 
                    border-radius: 6px; 
                    padding: 20px; 
                    margin: 25px 0; 
                }
                .message-label { 
                    font-weight: 600; 
                    color: #856404; 
                    margin-bottom: 10px; 
                }
                .message-content { 
                    color: #856404; 
                    line-height: 1.5; 
                }
                .next-steps { 
                    background-color: #e8f4f8; 
                    padding: 25px; 
                    border-radius: 8px; 
                    margin: 30px 0; 
                }
                .next-steps-title { 
                    font-size: 18px; 
                    font-weight: 600; 
                    margin-bottom: 15px; 
                    color: #0c5460; 
                }
                .steps-list { 
                    margin: 0; 
                    padding-left: 20px; 
                }
                .steps-list li { 
                    margin-bottom: 10px; 
                    color: #0c5460; 
                }
                .contact-box { 
                    background-color: #000000; 
                    color: #ffffff; 
                    padding: 25px; 
                    border-radius: 8px; 
                    margin: 30px 0; 
                }
                .contact-title { 
                    font-size: 18px; 
                    font-weight: 600; 
                    margin-bottom: 15px; 
                    color: #ffffff; 
                }
                .contact-info { 
                    line-height: 1.8; 
                }
                .footer { 
                    background-color: #f1f1f1; 
                    padding: 25px; 
                    text-align: center; 
                    font-size: 12px; 
                    color: #666666; 
                    border-top: 1px solid #dddddd; 
                }
                .footer-links { 
                    margin: 15px 0; 
                }
                .footer-links a { 
                    color: #000000; 
                    text-decoration: none; 
                    margin: 0 10px; 
                }
                .signature { 
                    margin: 25px 0; 
                    font-style: italic; 
                    color: #555555; 
                }
                @media (max-width: 600px) {
                    .content { padding: 25px 20px; }
                    .detail-item { flex-direction: column; }
                    .detail-label { min-width: auto; margin-bottom: 5px; }
                    .text-logo { font-size: 28px; }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <!-- Header with TEXT Logo -->
                <div class="header">
                    <div class="text-logo">KYRO<span class="logo-accent">SHIELD</span></div>
                    <p class="tagline">Secure. Comply. Evolve.</p>
                </div>
                
                <!-- Main Content -->
                <div class="content">
                    <h2 class="thank-you">Thank You for Contacting Kyroshield!</h2>
                    
                    <p class="greeting">Dear ${name},</p>
                    
                    <p>We have received your request for a quote regarding <strong>${serviceDisplayName}</strong> services. Our team will review your inquiry and contact you within 24 business hours.</p>
                    
                    <!-- Request Details -->
                    <div class="details-container">
                        <h3 class="details-title">📋 Your Request Details:</h3>
                        <div class="detail-item">
                            <span class="detail-label">Name:</span>
                            <span class="detail-value">${name}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Company:</span>
                            <span class="detail-value">${company}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Email:</span>
                            <span class="detail-value">${email}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Phone:</span>
                            <span class="detail-value">${phone}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Service:</span>
                            <span class="detail-value">${serviceDisplayName}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Submitted:</span>
                            <span class="detail-value">${new Date().toLocaleString('en-MY', { timeZone: 'Asia/Kuala_Lumpur' })}</span>
                        </div>
                    </div>
                    
                    <!-- Additional Message (if provided) -->
                    ${message ? `
                    <div class="message-box">
                        <div class="message-label">📝 Your Additional Message:</div>
                        <div class="message-content">${message}</div>
                    </div>
                    ` : ''}
                    
                    <!-- Next Steps -->
                    <div class="next-steps">
                        <h3 class="next-steps-title">🔄 What Happens Next:</h3>
                        <ol class="steps-list">
                            <li>Our team reviews your requirements</li>
                            <li>We prepare a customized quote based on your needs</li>
                            <li>A specialist contacts you to discuss details</li>
                            <li>We provide a comprehensive service proposal</li>
                        </ol>
                    </div>
                    
                    <!-- Contact Information -->
                    <div class="contact-box">
                        <h3 class="contact-title">📞 Contact Information</h3>
                        <div class="contact-info">
                            <p><strong>Email:</strong> contact@kyroshield.com</p>
                            <p><strong>Phone:</strong> +60 013-456 6146</p>
                            <p><strong>Address:</strong> Johor Bahru, Malaysia</p>
                            <p><strong>Business Hours:</strong> Monday - Friday, 9:00 AM - 6:00 PM</p>
                        </div>
                    </div>
                    
                    <!-- Signature -->
                    <div class="signature">
                        <p>Best regards,<br>
                        <strong>The Kyroshield Team</strong></p>
                    </div>
                </div>
                
                <!-- Footer -->
                <div class="footer">
                    <div class="footer-links">
                        <a href="https://www.kyroshield.com">Website</a>
                        <a href="https://www.kyroshield.com/services">Services</a>
                        <a href="https://www.kyroshield.com/contact">Contact</a>
                    </div>
                    <p>© ${new Date().getFullYear()} Kyroshield. All rights reserved.</p>
                    <p style="font-size: 11px; color: #999; margin-top: 15px;">
                        This is an automated message. Please do not reply directly to this email.<br>
                        For inquiries, email <a href="mailto:contact@kyroshield.com" style="color: #666;">contact@kyroshield.com</a>
                    </p>
                </div>
            </div>
        </body>
        </html>
        `;

        // Send both emails via SendGrid API
        const adminResult = await sendEmail(
            process.env.EMAIL_TO || 'contact@kyroshield.com',
            `New Quote Request: ${name} from ${company}`,
            adminHtml
        );

        const customerResult = await sendEmail(
            email,
            'Thank You for Your Quote Request - Kyroshield',
            customerHtml
        );

        console.log(`✅ Emails sent successfully via SendGrid API`);

        res.status(200).json({
            success: true,
            message: 'Thank you for your request! We have sent a confirmation email and will contact you within 24 hours.'
        });

    } catch (error) {
        console.error('❌ Email sending error:', error);
        
        let errorMessage = 'Failed to send email. Please try again later.';
        
        if (error.response && error.response.body && error.response.body.errors) {
            errorMessage = error.response.body.errors.map(err => err.message).join(', ');
        } else if (error.code === 'ETIMEDOUT' || error.code === 'ECONNECTION') {
            errorMessage = 'Email connection failed. Please try again later.';
        }

        res.status(500).json({
            success: false,
            message: errorMessage
        });
    }
});

// Updated error handling middleware
app.use((err, req, res, next) => {
    console.error('Global error handler:', err.message);
    console.error('Error stack:', err.stack);
    
    // Check if it's a CORS error
    if (err.message && (err.message.includes('CORS') || err.message.includes('origin'))) {
        return res.status(403).json({
            success: false,
            message: 'CORS Error: The request was blocked due to CORS policy.',
            error: 'CORS_POLICY_VIOLATION',
            details: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
    
    res.status(500).json({
        success: false,
        message: 'Something went wrong!',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// 404 handler
app.use((req, res) => {
    console.log(`404 Not Found: ${req.method} ${req.url}`);
    res.status(404).json({
        success: false,
        message: 'Endpoint not found'
    });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📧 Email service ready (SendGrid API)`);
    console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`========================================\n`);
    
    // Use Railway URL if available, otherwise localhost
    const railwayUrl = process.env.RAILWAY_STATIC_URL || `http://localhost:${PORT}`;
    console.log(`🔗 Important Endpoints:`);
    console.log(`   Health Check: ${railwayUrl}/api/health`);
    console.log(`   SendGrid Test: ${railwayUrl}/api/test-sendgrid`);
    console.log(`   CORS Test: ${railwayUrl}/api/cors-test`);
    console.log(`   Quote endpoint: POST ${railwayUrl}/api/send-email`);
    console.log(`   Test email: POST ${railwayUrl}/api/test-email\n`);
});