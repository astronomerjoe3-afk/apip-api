const fs = require('fs');
const path = 'scripts/seed_m1_module.py';
let text = fs.readFileSync(path, 'utf8');
text = text.replace('M1_CONTENT_VERSION = "20260315_m1_motion_extended_v1"', 'M1_CONTENT_VERSION = "20260315_m1_quest_log_v2"');
fs.writeFileSync(path, text, 'utf8');
console.log('ok');
