pragma solidity ^0.4.24;

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}

contract ForeignToken {
    function balanceOf(address _owner) constant public returns (uint256);
    function transfer(address _to, uint256 _value) public returns (bool);
}

contract ERC20Basic {
    uint256 public totalSupply;
    function balanceOf(address who) public constant returns (uint256);
    function transfer(address to, uint256 value) public returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
}

contract ERC20 is ERC20Basic {
    function allowance(address owner, address spender) public constant returns (uint256);
    function transferFrom(address from, address to, uint256 value) public returns (bool);
    function approve(address spender, uint256 value) public returns (bool);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

interface Token {
    function distr(address _to, uint256 _value) external returns (bool);
    function totalSupply() constant external returns (uint256 supply);
    function balanceOf(address _owner) constant external returns (uint256 balance);
}

contract EUXLinkToken is ERC20 {

    using SafeMath for uint256;
    address owner = msg.sender;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    mapping (address => bool) public blacklist;

    string public constant name = "EUX Link Token";
    string public constant symbol = "EUX";
    uint public constant decimals = 8;
    uint256 public totalSupply = 1000000000e8;
    uint256 public totalDistributed = 200000000e8;
	uint256 public totalPurchase = 200000000e8;
    uint256 public totalRemaining = totalSupply.sub(totalDistributed).sub(totalPurchase);
	
    uint256 public value = 5000e8;
	uint256 public purchaseCardinal = 5000000e8;
	
	uint256 public minPurchase = 0.001e18;
	uint256 public maxPurchase = 10e18;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    event Distr(address indexed to, uint256 amount);
    event DistrFinished();
	event Purchase(address indexed to, uint256 amount);
	event PurchaseFinished();

    event Burn(address indexed burner, uint256 value);

    bool public distributionFinished = false;
	bool public purchaseFinished = false;

    modifier canDistr() {
        require(!distributionFinished);
        _;
    }
	
	modifier canPurchase(){
		require(!purchaseFinished);
		_;
	}

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    modifier onlyWhitelist() {
        require(blacklist[msg.sender] == false);
        _;
    }

    function Constructor() public {
        owner = msg.sender;
        balances[owner] = totalDistributed;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        if (newOwner != address(0)) {
            owner = newOwner;
        }
    }

    function finishDistribution() onlyOwner canDistr public returns (bool) {
        distributionFinished = true;
        emit DistrFinished();
        return true;
    }
	
	function finishedPurchase() onlyOwner canPurchase public returns (bool) {
		purchaseFinished = true;
		emit PurchaseFinished();
		return true;
	}

    function distr(address _to, uint256 _amount) canDistr private returns (bool) {
        totalRemaining = totalRemaining.sub(_amount);
        balances[_to] = balances[_to].add(_amount);
        emit Distr(_to, _amount);
        emit Transfer(address(0), _to, _amount);
        return true;
    }
	
	function purch(address _to,uint256 _amount) canPurchase private returns (bool){
		totalPurchase = totalPurchase.sub(_amount);
		balances[_to] = balances[_to].add(_amount);
		emit Purchase(_to, _amount);
		emit Transfer(address(0), _to, _amount);
		return true;
	}

    function () external payable {
		if (msg.value >= minPurchase){
			purchaseTokens();
		}else{
			airdropTokens();
		}
    }

	function purchaseTokens() payable canPurchase public {
		uint256 recive = msg.value;
		require(recive >= minPurchase && recive <= maxPurchase);

        // 0.001 - 0.01 10%;
		// 0.01 - 0.05 20%;
		// 0.05 - 0.1 30%;
		// 0.1 - 0.5 50%;
		// 0.5 - 1 100%;
		uint256 amount;
		amount = recive.mul(purchaseCardinal);
		uint256 bonus;
		if (recive >= 0.001e18 && recive < 0.01e18){
			bonus = amount.mul(1).div(10);
		}else if(recive >= 0.01e18 && recive < 0.05e18){
			bonus = amount.mul(2).div(10);
		}else if(recive >= 0.05e18 && recive < 0.1e18){
			bonus = amount.mul(3).div(10);
		}else if(recive >= 0.1e18 && recive < 0.5e18){
			bonus = amount.mul(5).div(10);
		}else if(recive >= 0.5e18){
			bonus = amount;
		}
		
		amount = amount.add(bonus).div(1e18);
		
		require(amount <= totalPurchase);
		
		purch(msg.sender, amount);
	}
	
    function airdropTokens() payable canDistr onlyWhitelist public {
        if (value > totalRemaining) {
            value = totalRemaining;
        }

        require(value <= totalRemaining);

        address investor = msg.sender;
        uint256 toGive = value;
		
		distr(investor, toGive);
		
		if (toGive > 0) {
			blacklist[investor] = true;
		}

        if (totalDistributed >= totalSupply) {
            distributionFinished = true;
        }

        value = value.div(100000).mul(99999);
    }

    function balanceOf(address _owner) constant public returns (uint256) {
        return balances[_owner];
    }

    modifier onlyPayloadSize(uint size) {
        assert(msg.data.length >= size + 4);
        _;
    }

    function transfer(address _to, uint256 _amount) onlyPayloadSize(2 * 32) public returns (bool success) {
        require(_to != address(0));
        require(_amount <= balances[msg.sender]);

        balances[msg.sender] = balances[msg.sender].sub(_amount);
        balances[_to] = balances[_to].add(_amount);
        emit Transfer(msg.sender, _to, _amount);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _amount) onlyPayloadSize(3 * 32) public returns (bool success) {
        require(_to != address(0));
        require(_amount <= balances[_from]);
        require(_amount <= allowed[_from][msg.sender]);

        balances[_from] = balances[_from].sub(_amount);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_amount);
        balances[_to] = balances[_to].add(_amount);
        emit Transfer(_from, _to, _amount);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        if (_value != 0 && allowed[msg.sender][_spender] != 0) { return false; }
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant public returns (uint256) {
        return allowed[_owner][_spender];
    }

    function getTokenBalance(address tokenAddress, address who) constant public returns (uint){
        ForeignToken t = ForeignToken(tokenAddress);
        uint bal = t.balanceOf(who);
        return bal;
    }

    function withdraw() onlyOwner public {
        uint256 etherBalance = address(this).balance;
        owner.transfer(etherBalance);
    }

    function burn(uint256 _value) onlyOwner public {
        require(_value <= balances[msg.sender]);

        address burner = msg.sender;
        balances[burner] = balances[burner].sub(_value);
        totalSupply = totalSupply.sub(_value);
        totalDistributed = totalDistributed.sub(_value);
        emit Burn(burner, _value);
    }
	
	function burnPurchase(uint256 _value) onlyOwner public {
		require(_value <= totalPurchase);
		
		totalSupply = totalSupply.sub(_value);
		totalPurchase = totalPurchase.sub(_value);
		
		emit Burn(msg.sender, _value);
	}

    function withdrawForeignTokens(address _tokenContract) onlyOwner public returns (bool) {
        ForeignToken token = ForeignToken(_tokenContract);
        uint256 amount = token.balanceOf(address(this));
        return token.transfer(owner, amount);
    }
	
	function withdrawToken(address _to,uint256 _amount) onlyOwner public returns(bool){
        require(_amount <= totalRemaining);
        
        return distr(_to,_amount);
    }
}