fun main(args: Array<String>) {
    val cmd = args[0]
    // Indirect call: function reference
    val func = ProcessBuilder(cmd)
    func.start()
}
