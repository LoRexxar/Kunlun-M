// XSS test case
// document.write with location.search
var name = location.search;
document.write(name);
// end of file