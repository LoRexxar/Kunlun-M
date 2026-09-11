// This file exists solely to create a cross-language pollution hazard.
// PHP's $_GET["id"] should not be suppressed by any JS definitions here.
var get = function(id) { return db.escape(id); };
