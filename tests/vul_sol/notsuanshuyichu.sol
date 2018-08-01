pragma solidity ^0.4.16;

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {

    address public owner;

    /**
    * @dev The Ownable constructor sets the original `owner` of the contract to the sender
    * account.
    */
    function Ownable() public {
        owner = msg.sender;
    }

    /**
    * @dev Throws if called by any account other than the owner.
    */
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    /**
    * @dev Allows the current owner to transfer control of the contract to a newOwner.
    * @param newOwner The address to transfer ownership to.
    */
    function transferOwnership(address newOwner) onlyOwner public {
        require(newOwner != address(0));
        owner = newOwner;
    }

}
contract BWCToken is Ownable{

    uint256 public totalSupply;
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;

    string public constant name = "BWCOIN";
    string public constant symbol = "BWC";
    uint32 public constant decimals = 4;

    uint constant start = 1517418000;
    uint constant period = 87;
    uint256 public constant hardcap = 25 * 1000000 * (10 ** uint256(decimals));

    bool public transferAllowed = true;
    bool public mintingFinished = false;

    modifier whenTransferAllowed() {
        if(msg.sender != owner){
            require(transferAllowed);
        }
        _;
    }

    modifier saleIsOn() {
        require(now > start && now < start + period * 1 days);
        _;
    }

    modifier canMint() {
        require(!mintingFinished);
        _;
    }

    function transfer(address _to, uint256 _value) whenTransferAllowed public returns (bool) {
        require(_to != address(0));
        require(_value <= balances[msg.sender]);

        balances[msg.sender] = balances[msg.sender] - _value;
        balances[_to] = balances[_to] + _value;
        //assert(balances[_to] >= _value); no need to check, since mint has limited hardcap
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function balanceOf(address _owner) constant public returns (uint256 balance) {
        return balances[_owner];
    }

    function transferFrom(address _from, address _to, uint256 _value) whenTransferAllowed public returns (bool) {
        require(_to != address(0));
        require(_value <= balances[_from]);
        require(_value <= allowed[_from][msg.sender]);

        balances[_from] = balances[_from] - _value;
        balances[_to] = balances[_to] + _value;
        //assert(balances[_to] >= _value); no need to check, since mint has limited hardcap
        allowed[_from][msg.sender] = allowed[_from][msg.sender] - _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool) {
        //NOTE: To prevent attack vectors like the one discussed here:
        //https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729,
        //clients SHOULD make sure to create user interfaces in such a way
        //that they set the allowance first to 0 before setting it to another value for the same spender.

        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function allowTransfer() onlyOwner public {
        transferAllowed = true;
    }

    function mint(address _to, uint256 _value) onlyOwner saleIsOn canMint public returns (bool) {
        require(_to != address(0));

        if(_value + totalSupply <= hardcap){

            totalSupply = totalSupply + _value;

            assert(totalSupply >= _value);

            balances[msg.sender] = balances[msg.sender] + _value;
            assert(balances[msg.sender] >= _value);
            Mint(msg.sender, _value);

            transfer(_to, _value);
        }
        return true;
    }

    function finishMinting() onlyOwner public returns (bool) {
        mintingFinished = true;
        MintFinished();
        return true;
    }

    /**
     * @dev Burns a specific amount of tokens.
     * @param _value The amount of token to be burned.
     */
    function burn(uint256 _value) public returns (bool) {
        require(_value <= balances[msg.sender]);
        // no need to require value <= totalSupply, since that would imply the
        // sender's balance is greater than the totalSupply, which *should* be an assertion failure
        balances[msg.sender] = balances[msg.sender] - _value;
        totalSupply = totalSupply - _value;
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(_value <= balances[_from]);
        require(_value <= allowed[_from][msg.sender]);
        balances[_from] = balances[_from] - _value;
        allowed[_from][msg.sender] = allowed[_from][msg.sender] - _value;
        totalSupply = totalSupply - _value;
        Burn(_from, _value);
        return true;
    }

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(address indexed owner, address indexed spender, uint256 value);

    event Mint(address indexed to, uint256 amount);

    event MintFinished();

    event Burn(address indexed burner, uint256 value);

}