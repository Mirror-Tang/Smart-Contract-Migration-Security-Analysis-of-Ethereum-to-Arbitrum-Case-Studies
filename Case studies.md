# Smart Contract Migration: Security Analysis of Ethereum to Arbitrum - Case Studies

Below is the case study content mentioned in our research paper titled 'Smart Contract Migration: Security Analysis of Ethereum to Arbitrum'. Currently, our paper is under review. You can view our [preprint](https://arxiv.org/abs/2307.14773) version. Please note that this preprint is just a preliminary draft. The final version of our paper is much more comprehensive, and we will update the link here once the paper is published. If you're interested in our other research findings, you can find them here:

Regarding the research on smart contract security migration, we take Ethereum as the source chain for migration and Arbitrum as the target chain for migration. We summarize the problems encountered during the smart contract migration process, relevant smart contract examples, and the suggested modifications. We primarily organize them into four aspects: Arbitrum Messaging, Block Properties, Contract Address Alias, and Gas Fees. 



## Arbitrum Cross-chain Messaging

### issue:

Outdated off-chain data was obtained by the inactive sequencer

### case:

When obtaining off-chain data from an oracle, real-time requirements are crucial. If the sequencer goes down and transactions cannot be immediately executed, the contract will not be able to return accurate and real-time off-chain data.

Taking the [GLPOracle.sol ](https://github.com/sherlock-audit/2023-01-sentiment/blob/main/oracle/src/gmx/GLPOracle.sol#L47)contract as an example, we first introduce the main functionality of this contract. The getPrice() function is used to calculate the GLP/USD price. The constructor of the contract accepts two parameters: _manager and _ethFeed, representing the addresses of the GLPManager contract and the Ethereum price data source, respectively. The contract includes two functions: `getPrice()` and `getEthPrice()`. The `getEthPrice() `function retrieves the latest Ethereum price by calling `ethUsdPriceFeed.latestRoundData()` and performs validations for data expiration and negativity. ethUsdPriceFeed is an instance of an oracle contract used to provide external data services, and `latestRoundData()` is a public function of this contract that returns the latest ETH/USD price. The getPrice() function first calls `manager.getPrice(false)` to obtain the current price of the GLP token, and then calls getEthPrice() to retrieve the latest ETH/USD price. The GLP/USD price is calculated as **manager.getPrice(false) / (getEthPrice() * 1e4)**, where the GLP token price is divided by the ETH/USD price and then multiplied by 1e4. This is done to convert the price unit of ETH to USD in order to obtain the price unit of GLP.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {Errors} from "../utils/Errors.sol";
import {IOracle} from "../core/IOracle.sol";
import {IGLPManager} from "./IGLPManager.sol";
import {AggregatorV3Interface} from "../chainlink/AggregatorV3Interface.sol";

contract GLPOracle is IOracle {

    /// @notice address of gmx manager
    IGLPManager public immutable manager;
    /// @notice ETH USD Chainlink price feed
    AggregatorV3Interface immutable ethUsdPriceFeed;
    
    /**
        @notice Contract constructor
        @param _manager address of gmx vault
        @param _ethFeed address of eth usdc chainlink feed
    */
    constructor(IGLPManager _manager, AggregatorV3Interface _ethFeed) {
        manager = _manager;
        ethUsdPriceFeed = _ethFeed;
    }
    
    /// @inheritdoc IOracle
    function getPrice(address) external view returns (uint) {
        return manager.getPrice(false) / (getEthPrice() * 1e4);
    }
    
    function getEthPrice() internal view returns (uint) {
        (, int answer,, uint updatedAt,) = ethUsdPriceFeed.latestRoundData();
        if (block.timestamp - updatedAt >= 86400)
            revert Errors.StalePrice(address(0), address(ethUsdPriceFeed));
        if (answer <= 0)
            revert Errors.NegativePrice(address(0), address(ethUsdPriceFeed));
        return uint(answer);
    }
}
```

**Vulnerability:** There is a potential vulnerability when executing this contract on Arbitrum. When the contract reaches the statement ethUsdPriceFeed.latestRoundData(), it needs to access the oracle through the sequencer to obtain off-chain price data. If the sequencer goes down at this moment, the statement cannot be executed immediately. When the sequencer reconnects and executes this statement, it will retrieve outdated price data, which may be higher or lower than the actual price. Attackers can exploit the price difference between the actual price and the outdated price for profit.

Exploitation of this vulnerability: Assuming a user borrows using GLP tokens as collateral, if the sequencer goes down and the reconnected sequencer retrieves an outdated price higher than the actual price, the user can obtain better borrowing conditions. If the outdated price is lower than the actual price, the user can avoid liquidation.

The above vulnerability has been tested and confirmed to exist. The test code can be found at this link: https://github.com/sentimentxyz/oracle/blob/815233add2d23a7e2a2c5136504537b234a65c47/src/tests/GLPOracle.t.sol

### Vulnerability Fix Recommendations

To address the aforementioned vulnerability, we suggest querying the Chainlink L2 sequencer Uptime Feeds to determine the operational status of the sequencer. 

[Improve the implementation logic of the above code.](https://github.com/sentimentxyz/oracle/blob/main/src/gmx/GLPOracle.sol)：

```solidity
pragma solidity ^0.8.17; 

import {Errors} from "../utils/Errors.sol"; 
import {IOracle} from "../core/IOracle.sol"; 
import {IGLPManager} from "./IGLPManager.sol"; 
import {AggregatorV3Interface} from "../chainlink/AggregatorV3Interface.sol";

contract GLPOracle is IOracle { 

	/// @notice address of gmx manager 
 	IGLPManager public immutable manager; 
   	/// @notice ETH USD Chainlink price feed 
 	AggregatorV3Interface immutable ethUsdPriceFeed; 
   	/// @notice L2 Sequencer feed 
	AggregatorV3Interface immutable sequencer; 
   	/// @notice L2 Sequencer grace period 
 	uint256 private constant GRACE_PERIOD_TIME = 3600; 
 	
	constructor(IGLPManager _manager, AggregatorV3Interface _ethFeed, AggregatorV3Interface _sequencer) { 
		manager = _manager; 
 		ethUsdPriceFeed = _ethFeed; 
 		sequencer = _sequencer; 
 	} 
 	
	function getPrice(address) external view returns (uint256) { 
		if (!isSequencerActive()) revert Errors.L2SequencerUnavailable(); 
 		return manager.getPrice(false) / (getEthPrice() * 1e4); 
	} 
	
	function getEthPrice() internal view returns (uint256) { 
		(, int256 answer,, uint256 updatedAt,) = ethUsdPriceFeed.latestRoundData(); 
   		if (block.timestamp - updatedAt >= 86400) { 
			revert Errors.StalePrice(address(0), address(ethUsdPriceFeed)); 
 		} 
   		if (answer <= 0) { 
 			revert Errors.NegativePrice(address(0), address(ethUsdPriceFeed)); 
 		} 
   		return uint256(answer); 
   	} 
   	
	function isSequencerActive() internal view returns (bool) { 
 		(, int256 answer, uint256 startedAt,,) = sequencer.latestRoundData(); 
 		if (block.timestamp - startedAt <= GRACE_PERIOD_TIME || answer == 1) { 
 			return false; 
 		} 
 	    return true; 
 	} 
 } 
```



In the `getPrice()` function, the first step is to call the `isSequencerActive()` function to check if the sequencer is in a normal operational state. If it is not normal, the function will revert. Only when the sequencer is running normally, the code to retrieve off-chain price data and calculate the GLP price will be executed. This logic aligns with the main functionality of the GLPOracle.sol contract mentioned above. 

The is SequencerActive() function retrieves the status of the sequencer by calling `sequencer.latestRoundData()`. The `sequencer` is an instance of an oracle contract used to provide external data services, and it primarily uses the `sequencer uptime feed proxy address` for `configuration. latestRoundData()` is a public function in that contract, and it returns the status of the sequencer. If it is running normally, the function returns true; otherwise, it returns false.

## Block Properties

### Issue：

Logic errors based on time

### Case1

The smart contract project for financial derivatives trading relies on `block.number` to calculate time intervals. Specifically, the [_checkDelay()](https://github.com/code-423n4/2022-12-tigris/blob/588c84b7bb354d20cbca6034544c4faa46e6a80e/contracts/Trading.sol#L857-L868) function implements a locking mechanism to check if there is enough time between opening and closing positions. This is done to prevent profiting from opening and closing positions with two different prices in the same transaction within the valid signature pool.

```solidity
function _checkDelay(uint _id, bool _type) internal {

	unchecked {
		Delay memory _delay = blockDelayPassed[_id];
		
		if (_delay.actionType == _type) {
			blockDelayPassed[_id].delay = block.number + blockDelay;
		} else {
			if (block.number < _delay.delay) revert("0");
			blockDelayPassed[_id].delay = block.number + blockDelay;
			blockDelayPassed[_id].actionType = _type;
        }
	}
}
```

**Vulnerability:** While this structure works fine on Ethereum, it has issues when used on Arbitrum. The sequencer returns the most recently synchronized L1 block number based on `block.number` every minute. This one-minute time interval can be exploited. Users can open a position before the synchronization occurs (e.g., at 12:00:45 am, L2 obtains L1 block number 1000), and then close it in the next block (e.g., at 12:01 am, L2 obtains number 1004). It may seem like there have been 5 L1 blocks (60/12) since the last transaction, but in reality, there haven't been enough L1 blocks delayed to bypass the locking protection.

Malicious traders can exploit this by continuously updating the block delay in `_checkDelay()` and increasing the stop-loss threshold, enabling risk-free trading. This is a problem inherent to L1 itself, but if it occurs on Arbitrum, the impact will be amplified as malicious traders can modify the time delay for closing positions without going through the `blockDelay`.

### Case 2

In an Arbitrum smart contract, there are check statements to restrict users from performing multiple operations within a single block. For example, the time check statements in the [openPosition](https://github.com/tintinweb/smart-contract-sanctuary-arbitrum/blob/662d22a0f98c6a0c8ef23e43ac6d6a3eac5968da/contracts/testnet/aa/aa1A6AD03E098A88e55AfBdf1c2aCc9DB9FFCC87_MarginFactory.sol#L185) and [closePosition](https://github.com/tintinweb/smart-contract-sanctuary-arbitrum/blob/662d22a0f98c6a0c8ef23e43ac6d6a3eac5968da/contracts/testnet/aa/aa1A6AD03E098A88e55AfBdf1c2aCc9DB9FFCC87_MarginFactory.sol#L258) functions are as follows:

```solidity
require(
	// Restrict users from performing multiple operations within a single block
    traderLatestOperation[trader] != block.number, "ONE_BLOCK_TWICE_OPERATION"
);
```

**Vulnerability:** Arbitrum updates `block.number` every minute. However, in reality, several blocks may have passed on L1, but the obtained L1 block number on Arbitrum remains unchanged. This causes a delay of up to one minute in the operations performed in the example code.

## Contract Address Alias

### Issue：

The permission check failed

### Case

Uniswap Labs did not consider Address Alias when deploying to Arbitrum.

```solidity
function setOwner(address _owner) external override {

	require(msg.sender == owner);
    emit OwnerChanged(owner, _owner);
    owner = _owner;
}
```

**Vulnerability:** When deploying the [Uniswap v3 Factory](https://arbiscan.io/address/0x1F98431c8aD98523631AE4a59f267346ea31F984#contracts) to Arbitrum, the owner of the Factory contract is set to the original address of the Timelock contract on Ethereum using the `setOwner()` function. However, during the L1-to-L2 message call, the `msg.sender` obtained is the alias address of the Timelock contract on Arbitrum. As a result, the permission check cannot be passed. Additionally, as this alias address is an externally owned account (EOA) and no one possesses the private key for this address, the owner cannot be modified, and functions that require owner permissions cannot be executed on Arbitrum for the Factory contract.

**Solution:**

To address this issue, Arbitrum temporarily disabled address aliasing for the Timelock contract. In the Inbox contract, there is a specific method created for Uni called `uniswapCreateRetryableTicket`. In the absence of address aliasing, the Uniswap Factory contract sends a cross-chain message from the Ethereum Timelock contract to invoke the `setOwner` function on the Arbitrum Uniswap Factory, setting the owner to the alias address `0x2BAD8182C09F50c8318d769245beA52C32Be46CD` of the Ethereum Timelock. This ensures compliance with the permission check in the Factory contract.

## Gas Fees

### Issue：

DOS Attack

### Case 1:

Each block has an upper limit on the amount of gas that can be consumed. If the gas spent exceeds this limit, the transaction will fail. In a contract, there may be arrays without explicit size restrictions or constraints. An attacker may intentionally add a large amount of data to an array in a function or contract that processes the array, causing the gas to be exhausted during the loop, rendering the function unable to execute successfully.

This situation is prone to occur in crowdfunding projects, auction projects, or other contract projects that may involve batch refunds or other batch operations. For example, an attacker may add a large number of addresses to the contract, each requiring a very small refund. When the project contract attempts to refund by iterating through the array, the loop count becomes enormous due to the attacker's addition of a large number of addresses, and the gas cost for this transaction may ultimately exceed the gas limit, resulting in the inability to refund. Since gas prices are lower on Arbitrum, the attacker's cost is reduced, making such attacks more likely to occur.

[In the code snippet below](https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/#gas-limit-dos-on-the-network-via-block-stuffing), a for loop is used to iterate through each address in the `Addresses` array.

```solidity
address[] private Addresses;

mapping (address => uint) public fundAmount;

function refundAll() public {

	for(uint x; x < Addresses.length; x++) {       
		require(token.transfer(address(this),Addresses[x],fundAmount[Addresses[x]]));
	}
}
```

**Vulnerability:** In each iteration, it uses a require statement to invoke the `transfer()` function of the Token contract, transferring the funds stored in the contract to the corresponding addresses. If the attacker adds a large number of addresses to the `Addresses` array, and each address requires a very small refund amount, the loop in the refundAll function will execute a significant number of iterations. When the loop count exceeds the gas limit of the block, the transaction will fail, resulting in the inability to successfully execute the refunds. In this scenario, the attacker can prevent the refund operation by depleting the gas, thereby affecting the normal operation of the contract.

### Vulnerability fix recommendation 1

To address this issue, several approaches can be considered:

1. Limiting the array size: Adding a function or modifier to the contract that limits the size of the Addresses array can prevent attackers from adding an excessive number of addresses, thereby reducing the number of iterations in the loop.

2. Batch processing: Dividing the refund operation into multiple loops, with each loop processing a certain number of addresses, can prevent excessive data processing in a single iteration and reduce the number of loops.

3. Using mappings instead of arrays: Consider using mappings instead of arrays to store addresses and refund amounts. Mappings have no size limitation, and refund operations can be handled by iterating through the keys of the mapping without the need for a loop.

4. Using optimized algorithms: Employ more efficient algorithms to handle refund operations, reducing the number of iterations and gas consumption. For example, binary search or other efficient search algorithms can be used to locate specific addresses for refund operations.

Below is an example code demonstrating how to use batch processing to avoid gas limitations. We introduce a new parameter, batchSize, in the refundAll function. This parameter determines the number of addresses processed in each iteration. The loop pauses after processing the specified number of addresses and then continues with the next batch of addresses. This approach prevents excessive data processing in a single iteration.

```solidity
pragma solidity ^0.8.0;

contract Token {
    mapping (address => uint) public balances;
    
    function transfer(address from, address to, uint amount) public returns (bool) {
        require(balances[from] >= amount, "Insufficient balance");
        balances[from] -= amount;
        balances[to] += amount;
        return true;
    }
}

contract RefundContract {
    address[] private Addresses;
    mapping (address => uint) public fundAmount;
    Token private token;
    
    constructor(address _token) {
        token = Token(_token);
    }
    
    function addAddress(address _address, uint _amount) public {
        Addresses.push(_address);
        fundAmount[_address] = _amount;
    }
    
    function refundAll(uint batchSize) public {
        uint totalAddresses = Addresses.length;
        uint processedAddresses;
        
        while (processedAddresses < totalAddresses) {
            uint end = processedAddresses + batchSize;
            if (end > totalAddresses) {
                end = totalAddresses;
            }
            
            for (uint i = processedAddresses; i < end; i++) {
                require(token.transfer(address(this), Addresses[i], fundAmount[Addresses[i]]));
            }
            
            processedAddresses = end;
        }
    }
}
```

### Case 2

[The following example](https://github.com/sherlock-audit/2023-02-surge/blob/main/surge-protocol-v1/src/Pool.sol#L216-L263) illustrates the security issue caused by frequent small transactions on Arbitrum. In a mortgage lending contract, the calculation statement for updating the collateral ratio is as follows:

```solidity
uint change = timeDelta * _maxCollateralRatioMantissa / _collateralRatioRecoveryDuration;
```

**Vulnerability:** By rapidly refreshing or setting the _collateralRatioRecoveryDuration greater than _maxCollateralRatioMantissa, it is possible to prevent the update of the collateral ratio. Specifically, let's consider a loan pool where the loan token is WBTC and the collateral token is DAI, with each DAI allowing borrowing of only 1/10000 BTC (with a maximum interest rate of $10,000 per BTC). The _maxCollateralRatioMantissa is set to 1e14, and the _collateralRatioRecoveryDuration is set to 1e15. If an attacker makes frequent deposits of 1 wei WBTC within every 10 seconds, the value of (timeDelta * _maxCollateralRatioMantissa) will always be less than _collateralRatioRecoveryDuration, preventing the update of the collateral ratio. This disrupts the protocol's adaptive pricing mechanism and forces users to borrow at the current interest rate. As the pool's collateral ratio and pool exchange rate will no longer be updated, depositors may experience loss of funds.

### Vulnerability fix recommendation 2

To address the vulnerability mentioned above, which involves frequent deposits of 1 wei WBTC preventing the update of the collateral ratio, the following measures can be implemented to mitigate the issue:

1. Adding a minimum deposit amount restriction: Set a minimum deposit amount to prevent frequent small deposits. By establishing a reasonable minimum deposit amount, any deposits below this threshold will be rejected.

2. Adding a deposit time interval restriction: Limit the time interval between deposits to prevent frequent deposits. Set a reasonable time interval, such as allowing only one deposit per hour.
3. Implementing a deposit threshold: Introduce a deposit threshold that requires the deposit amount to reach a certain threshold in order to update the collateral ratio.
4. Introducing a cooldown period: After a deposit is made, introduce a cooldown period. The cooldown period is calculated independently for each user, meaning that each user will have their own cooldown period after making a deposit. Prevent further deposits within the cooldown period, and the length of the cooldown period can be set based on specific circumstances.

Here is an example code that checks for the minimum deposit amount, deposit threshold, and cooldown period when a user makes a deposit. It also updates the collateral ratio and the depositor's last deposit time if all conditions are met.

```solidity
pragma solidity ^0.8.0;

contract CollateralRatioProtection {
    uint256 private constant MIN_DEPOSIT_AMOUNT = 1e8; // 1 BTC
    uint256 private constant DEPOSIT_THRESHOLD = 1e6; // 0.01 BTC
    uint256 private constant DEPOSIT_COOLDOWN = 1 hours;

    mapping(address => uint256) private lastDepositTime;

    function deposit(uint256 amount) external {
        require(amount >= MIN_DEPOSIT_AMOUNT, "Deposit amount too small");
        require(amount >= DEPOSIT_THRESHOLD, "Deposit amount below threshold");

        require(block.timestamp >= lastDepositTime[msg.sender] + DEPOSIT_COOLDOWN, "Deposit cooldown period not elapsed");

        // Update collateral ratio and other necessary actions
        // ...

        lastDepositTime[msg.sender] = block.timestamp;
    }
}
```



## What else are we doing?

If you're interested in our other research findings, you can find them here:



**EIP Security Analysis Application Program Standards Attack Events**

We conducted research on the current state of EIP security, performed case studies, and provided security recommendations. The goal is to gain a comprehensive understanding of the security features and potential risks of these proposals, and to propose practical solutions to enhance the security of EIPs.

https://github.com/Mirror-Tang/EIP_Security_Analysis_Application_Program_Standards_Attack_Events



**Academic Writing**

We excel at problem identification, whether it is in the field of smart contract security audits or academia. Our expertise in smart contract knowledge and academic writing enables us to produce effective and easily understandable content. We are also passionate about problem-solving and spreading blockchain knowledge across various industries. For example:

https://www.science.org/doi/10.1126/scirobotics.abm4636

https://www.science.org/doi/10.1126/sciadv.abd2204#elettersSection

Simple features and minor vulnerabilities often lead to major troubles. However, many of these troubles are caused by disclosed vulnerabilities or features. There is still a long way to go in terms of developer education, and I believe I have been on that path...



## About Me

I am an interdisciplinary blockchain scientist involved in researching blockchain engineering and social sciences. My areas of focus include smart contract security, performance of distributed systems, and analysis of data and economics in the fee market. I am intrigued by comprehending the intricate interplay between social and technological aspects in collective decision-making within the blockchain ecosystem. Additionally, I strive to strike a harmonious balance between the performance, security, and technological freedom of blockchains. Cybersecurity and data-driven decision-making have numerous applications in the realm of blockchain. They can aid in preventing data validation errors, service interruptions or rollbacks, as well as fund theft. Moreover, they can enhance the sustainability of the economic model, thereby addressing significant challenges.

Twitter: @0x677

Linkedin： https://www.linkedin.com/in/mt2/

Google Scholar： https://scholar.google.com/citations?view_op=list_works&hl=zh-CN&hl=zh-CN&user=_F_wFPAAAAAJ
