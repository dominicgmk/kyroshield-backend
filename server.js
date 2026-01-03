const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const sgMail = require('@sendgrid/mail');
const rateLimit = require('express-rate-limit');

// Load environment variables
dotenv.config();

// Initialize SendGrid
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const app = express();

// ================ SECURITY & PERFORMANCE MIDDLEWARE ================

// Trust Railway's proxy for rate limiting
app.set('trust proxy', 1);

// Request ID and logging middleware (SERVER SIDE ONLY - no browser output)
app.use((req, res, next) => {
    const requestId = Date.now().toString(36) + Math.random().toString(36).substr(2);
    req.requestId = requestId;
    req.startTime = Date.now();
    
    // Server logs only - not sent to browser
    console.log(`📥 [${requestId}] ${req.method} ${req.path} from ${req.ip}`);
    
    next();
});

// Security headers middleware
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    
    next();
});

// CORS Configuration
const corsOptions = {
    origin: function(origin, callback) {
        if (!origin) {
            return callback(null, true);
        }
        
        const normalizedOrigin = origin.replace(/\/$/, '').toLowerCase();
        
        const allowedOrigins = [
            'https://www.kyroshield.com',
            'https://kyroshield.com',
            'http://localhost:5501',
            'http://127.0.0.1:5501',
            'https://kyroshield-backend.up.railway.app'
        ].map(url => url.replace(/\/$/, '').toLowerCase());
        
        if (process.env.NODE_ENV === 'development') {
            return callback(null, true);
        }
        
        if (allowedOrigins.includes(normalizedOrigin)) {
            return callback(null, true);
        }
        
        if (normalizedOrigin === 'https://www.kyroshield.com' || 
            normalizedOrigin === 'https://kyroshield.com') {
            return callback(null, true);
        }
        
        if (normalizedOrigin.includes('localhost:5501') || 
            normalizedOrigin.includes('127.0.0.1:5501')) {
            return callback(null, true);
        }
        
        if (normalizedOrigin.includes('railway.app')) {
            return callback(null, true);
        }
        
        return callback(new Error('CORS policy violation'), false);
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Request size limits
app.use(express.json({ limit: '50kb' })); // Increased for HTML emails
app.use(express.urlencoded({ extended: true, limit: '50kb' }));

app.use((req, res, next) => {
    const contentLength = parseInt(req.headers['content-length'] || '0');
    if (contentLength > 51200) { // 50KB
        return res.status(413).json({
            success: false,
            message: 'Request payload too large.'
        });
    }
    next();
});

// Response timing middleware
app.use((req, res, next) => {
    const start = Date.now();
    
    // Store original end method
    const originalEnd = res.end;
    
    res.end = function(...args) {
        const duration = Date.now() - start;
        
        // Log completion server-side only
        console.log(`✅ [${req.requestId}] Completed in ${duration}ms`);
        
        // Add response time header (optional)
        res.setHeader('X-Response-Time', `${duration}ms`);
        
        // Call original end method
        return originalEnd.apply(res, args);
    };
    
    next();
});

// ================ INPUT SANITIZATION ================

const sanitizeInput = (input) => {
    if (typeof input !== 'string') return input;
    return input
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;')
        .replace(/\\/g, '&#x5C;')
        .replace(/`/g, '&#96;')
        .trim();
};

// ================ RATE LIMITING ================

const ipLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: {
        success: false,
        message: 'Too many requests. Please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.method === 'OPTIONS',
    keyGenerator: (req) => req.ip
});

const emailLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: {
        success: false,
        message: 'Too many requests from this email. Please try again later.'
    },
    skip: (req) => req.method === 'OPTIONS',
    keyGenerator: (req) => {
        return req.body?.email ? req.body.email.toLowerCase() : req.ip;
    }
});

// ================ EMAIL FUNCTIONS ================

const sendEmail = async (to, subject, html, text = null) => {
    try {
        // Create plain text version
        const plainText = text || html
            .replace(/<br\s*\/?>/gi, '\n')
            .replace(/<p>/gi, '\n')
            .replace(/<\/p>/gi, '\n')
            .replace(/<[^>]*>/g, '')
            .replace(/&nbsp;/g, ' ')
            .replace(/&amp;/g, '&')
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .replace(/\s+/g, ' ')
            .trim();
        
        const msg = {
            to,
            from: {
                email: process.env.EMAIL_FROM || 'contact@kyroshield.com',
                name: 'Kyroshield'
            },
            subject: subject.substring(0, 78),
            html,
            text: plainText,
            headers: {
                'X-Entity-Ref-ID': Date.now().toString(),
                'List-Unsubscribe': '<mailto:contact@kyroshield.com?subject=Unsubscribe>'
            },
            categories: ['quote-request', 'kyroshield-website']
        };
        
        console.log(`📧 Sending email to ${to}`);
        const result = await sgMail.send(msg);
        
        console.log(`✅ Email sent: ${result[0].headers['x-message-id']}`);
        return { 
            success: true, 
            messageId: result[0].headers['x-message-id'],
            statusCode: result[0].statusCode
        };
        
    } catch (error) {
        console.error('❌ SendGrid error:', error.message);
        throw error;
    }
};

// ================ API ENDPOINTS ================

// Health check endpoint
app.get('/api/health', (req, res) => {
    const healthData = {
        success: true,
        message: 'Kyroshield Backend Server',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        email: {
            configured: !!process.env.SENDGRID_API_KEY,
            service: 'SendGrid API'
        }
    };
    
    res.json(healthData);
});

// SendGrid test endpoint
app.get('/api/test-sendgrid', async (req, res) => {
    try {
        if (!process.env.SENDGRID_API_KEY) {
            return res.status(500).json({
                success: false,
                message: 'Email service not configured.'
            });
        }
        
        await sgMail.send({
            to: 'test@example.com',
            from: process.env.EMAIL_FROM || 'test@kyroshield.com',
            subject: 'SendGrid Test',
            text: 'Testing SendGrid connection',
            html: '<p>Testing SendGrid connection</p>'
        });
        
        res.json({
            success: true,
            message: 'SendGrid connection successful'
        });
        
    } catch (error) {
        console.error('SendGrid test error:', error.message);
        
        let errorMessage = 'SendGrid connection failed.';
        
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
        message: 'CORS test endpoint'
    });
});

// Test email endpoint
app.post('/api/test-email', ipLimiter, async (req, res) => {
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
                message: 'Email service not configured.'
            });
        }

        const html = `<p>This is a test email from Kyroshield server.</p>
                      <p>Timestamp: ${new Date().toLocaleString()}</p>`;

        await sendEmail(testEmail, 'Test Email from Kyroshield', html);
        
        res.status(200).json({
            success: true,
            message: `Test email sent successfully`
        });

    } catch (error) {
        console.error('Test email error:', error.message);
        
        let errorMessage = 'Failed to send test email.';
        
        res.status(500).json({
            success: false,
            message: errorMessage
        });
    }
});

// Email sending endpoint (for quote form)
app.post('/api/send-email', ipLimiter, emailLimiter, async (req, res) => {
    try {
        // Sanitize ALL inputs
        const name = sanitizeInput(req.body.name);
        const company = sanitizeInput(req.body.company);
        const email = sanitizeInput(req.body.email).toLowerCase();
        const phone = sanitizeInput(req.body.phone);
        const service = sanitizeInput(req.body.service);
        const message = sanitizeInput(req.body.message);

        console.log(`📨 New quote request from ${name} at ${company}`);

        // Validation
        if (!name || !company || !email || !phone || !service) {
            return res.status(400).json({
                success: false,
                message: 'Please fill in all required fields.'
            });
        }

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
                message: 'Email service is currently unavailable.'
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

        // Admin email HTML (your template)
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
                    </div>
                </div>
                <div class="footer">
                    <p>This email was automatically generated from the Kyroshield website contact form.</p>
                </div>
            </div>
        </body>
        </html>
        `;

        // Customer email HTML (your template)
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

        // Send both emails
        await sendEmail(
            process.env.EMAIL_TO || 'contact@kyroshield.com',
            `New Quote Request: ${name} from ${company}`,
            adminHtml
        );

        await sendEmail(
            email,
            'Thank You for Your Quote Request - Kyroshield',
            customerHtml
        );

        console.log(`✅ Quote request processed: ${name} from ${company}`);

        res.status(200).json({
            success: true,
            message: 'Thank you for your request! We have sent a confirmation email and will contact you within 24 hours.'
        });

    } catch (error) {
        console.error('Email sending error:', error.message);
        
        let errorMessage = 'Failed to send email. Please try again later.';
        
        res.status(500).json({
            success: false,
            message: errorMessage
        });
    }
});

// ================ ERROR HANDLING ================

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Endpoint not found'
    });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Server error:', err.message);
    
    const isProduction = process.env.NODE_ENV === 'production';
    
    if (err.message && (err.message.includes('CORS') || err.message.includes('origin'))) {
        return res.status(403).json({
            success: false,
            message: 'Request blocked due to security policy.'
        });
    }
    
    res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: isProduction ? undefined : err.message
    });
});

// ================ SERVER STARTUP ================

const PORT = process.env.PORT || 3000;

// Graceful shutdown handlers
const shutdown = (signal) => {
    console.log(`\n⚠️ Received ${signal}. Shutting down gracefully...`);
    
    if (server) {
        server.close(() => {
            console.log('✅ HTTP server closed');
            process.exit(0);
        });
        
        // Force shutdown after 10 seconds
        setTimeout(() => {
            console.error('⚠️ Could not close connections in time, forcing shutdown');
            process.exit(1);
        }, 10000);
    } else {
        process.exit(0);
    }
};

const server = app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📧 Email service ready (SendGrid API)`);
    console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`========================================\n`);
});

// Handle shutdown signals
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Handle uncaught errors
process.on('uncaughtException', (error) => {
    console.error('💥 UNCAUGHT EXCEPTION:', error);
    shutdown('UNCAUGHT_EXCEPTION');
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('💥 UNHANDLED REJECTION at:', promise, 'reason:', reason);
    shutdown('UNHANDLED_REJECTION');
});