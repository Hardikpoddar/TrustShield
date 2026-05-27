use('trustshield');

// ── 1. USERS ──
db.createCollection('users', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['username', 'password'],
      properties: {
        user_id:    { bsonType: 'int' },
        username:   { bsonType: 'string' },
        password:   { bsonType: 'string' },
        email:      { bsonType: 'string' },
        phone:      { bsonType: 'string' },
        created_at: { bsonType: 'string' }
      }
    }
  },
  validationAction: 'warn'
});

// ── 2. ADMIN ──
db.createCollection('admin', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['username', 'password'],
      properties: {
        admin_id:  { bsonType: 'int' },
        username:  { bsonType: 'string' },
        password:  { bsonType: 'string' },
        email:     { bsonType: 'string' }
      }
    }
  },
  validationAction: 'warn'
});

// ── 3. LOGIN ──
db.createCollection('login', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['user_id'],
      properties: {
        login_id:    { bsonType: 'int' },
        user_id:     { bsonType: 'string' },
        login_time:  { bsonType: 'string' },
        logout_time: { bsonType: 'string' }
      }
    }
  },
  validationAction: 'warn'
});

// ── 4. DETECTION_LOG ──
db.createCollection('detection_log', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['input_text', 'is_scam'],
      properties: {
        log_id:     { bsonType: 'int' },
        user_id:    { bsonType: 'string' },
        scanned_at: { bsonType: 'string' },
        input_text: { bsonType: 'string' },
        is_scam:    { bsonType: 'bool' },
        reason:     { bsonType: 'string' },
        risk_level: {
          bsonType: 'string',
          enum: ['Low', 'Medium', 'High']
        }
      }
    }
  },
  validationAction: 'warn'
});

// ── 5. URL_SCAN ──
db.createCollection('url_scan', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['url_text', 'is_scam'],
      properties: {
        scan_id:    { bsonType: 'int' },
        user_id:    { bsonType: 'string' },
        url_text:   { bsonType: 'string' },
        is_scam:    { bsonType: 'bool' },
        scan_time:  { bsonType: 'string' },
        risk_level: {
          bsonType: 'string',
          enum: ['Low', 'Medium', 'High']
        }
      }
    }
  },
  validationAction: 'warn'
});

// ── 6. URL_FEATURES ──
db.createCollection('url_features', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['url_scan_id'],
      properties: {
        feature_id:  { bsonType: 'int' },
        url_scan_id: { bsonType: 'string' },
        length:      { bsonType: 'int' },
        num_dots:    { bsonType: 'int' },
        blacklist:   { bsonType: 'bool' },
        https:       { bsonType: 'bool' },
        symbols:     { bsonType: 'bool' }
      }
    }
  },
  validationAction: 'warn'
});

// ── 7. REPORT ──
db.createCollection('report', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['message_content', 'report_type'],
      properties: {
        report_id:       { bsonType: 'int' },
        user_id:         { bsonType: 'string' },
        message_content: { bsonType: 'string' },
        submitted_at:    { bsonType: 'string' },
        report_type: {
          bsonType: 'string',
          enum: [
            'Phishing Email',
            'Suspicious SMS',
            'Suspicious Message',
            'Suspicious Link'
          ]
        },
        status: {
          bsonType: 'string',
          enum: ['Pending', 'Reviewed', 'Resolved']
        }
      }
    }
  },
  validationAction: 'warn'
});

// ── 8. RISK_KEYWORD ──
db.createCollection('risk_keyword', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['keyword', 'risk_level', 'category'],
      properties: {
        keyword_id: { bsonType: 'int' },
        added_by:   { bsonType: 'string' },
        keyword:    { bsonType: 'string' },
        risk_level: {
          bsonType: 'string',
          enum: ['Low', 'Medium', 'High']
        },
        category:   { bsonType: 'string' },
        created_at: { bsonType: 'string' }
      }
    }
  },
  validationAction: 'warn'
});

// ── 9. REPORT_KEYWORD (junction table) ──
db.createCollection('report_keyword', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['report_id', 'keyword_id'],
      properties: {
        report_id:  { bsonType: 'string' },
        keyword_id: { bsonType: 'string' }
      }
    }
  },
  validationAction: 'warn'
});

// ── INDEXES ──
db.users.createIndex({ username: 1 });
db.users.createIndex({ email: 1 });
db.login.createIndex({ user_id: 1 });
db.detection_log.createIndex({ user_id: 1 });
db.detection_log.createIndex({ scanned_at: 1 });
db.url_scan.createIndex({ user_id: 1 });
db.url_scan.createIndex({ scan_time: 1 });
db.risk_keyword.createIndex({ keyword: 1 });
db.report.createIndex({ user_id: 1 });
db.report.createIndex({ submitted_at: 1 });
db.report_keyword.createIndex({ report_id: 1 });
db.report_keyword.createIndex({ keyword_id: 1 });

print('✅ All 9 collections created successfully!');