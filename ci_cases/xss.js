// XSS test case
// document.write with location.search
function writeName() {
    var name = location.search;
    document.write(name);
}
// end of file
