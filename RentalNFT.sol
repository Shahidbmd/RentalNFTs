// SPDX-License-Identifier: MIT
pragma solidity ^0.8.2;

import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

// when NFT is rented, the reward should be splitted into owner and NFT holder
// owner will set the reward ratio
// the ratio should be set in constructor

// when NFT is rented, it should not be transferable

contract NFT is ERC721,Pausable, Ownable,ReentrancyGuard {
    using Counters for Counters.Counter;
    Counters.Counter private nftId;
    using SafeERC20 for IERC20;
    using SafeMath for uint256;
    string private baseURI;
    bool private allowedTosetUser;

    // Logged when the user of a token assigns a new user or updates expires
    /// @notice Emitted when the `user` of an NFT or the `expires` of the `user` is changed
    /// The zero address for user indicates that there is no user address
    event UpdateUser(uint256 indexed nftId, address indexed user, uint64 expires);

    struct TenentInfo
    {
        address user;   // address of user role
        uint64 expires; // unix timestamp, user expires
    }
    mapping (uint256  => TenentInfo) internal _users;

    struct NFTData {
        uint256 category;
        uint256 rentPrice;
    }
    mapping(uint256 => NFTData) private nftRentInfo;

    // category => price
    mapping(uint256 => uint256) private pricePerSec;
    mapping(uint256 => uint256) private pricePerNFTMint;
    IERC20 paymentToken;
    //total Supply
    uint256 constant public totalSupply = 150;
    //mapping category => count minted NFTs
    mapping( uint256 => uint256) private mintedWithinCategoryLimit;

    //set Category to Limit of NFTs
    mapping(uint256 => uint256) private categoryNFTsLimit;

    constructor(string memory name_, string memory symbol_, IERC20 _paymentToken) ERC721(name_,symbol_)
     {  require(address(_paymentToken) != address(0), "Invalid Token Address");
         nftId.increment();
         paymentToken = _paymentToken;
     }
    
    //set Base URI
    function setBaseURI(string memory _baseUri) external onlyOwner {
        require (bytes(_baseUri).length > 0, "Empty Uri not allowed");
        baseURI= _baseUri;
    }

    function _baseURI() internal view override returns (string memory) {
        return baseURI;
    }

    // hotel owner can set the data
    function setNftData(uint256 _category, uint256 _pricePerSecRent , uint256 _pricePerNFTMint) external onlyOwner {
        _isValidCategory(_category);
        pricePerSec[_category] = _pricePerSecRent;
        pricePerNFTMint[_category] = _pricePerNFTMint;
    }
    //set category minting Limit
    function setCategoryLimit(uint256 _category, uint256 _nftsLimit) external onlyOwner {
        categoryNFTsLimit[_category] = _nftsLimit;
    }

    function getCategoryMintLimit(uint256 _category) external view returns(uint256) {
        return categoryNFTsLimit[_category];
    }

    function getMintedNFTs(uint256 _category) external view returns(uint256) {
        return mintedWithinCategoryLimit[_category];
    }

    function mint(uint256 _category) external whenNotPaused nonReentrant {
        _isValidCategory(_category);
        require(mintedWithinCategoryLimit[_category] < categoryNFTsLimit[_category] , "Can't mint more in this Category");
        uint256 _nftId = nftId.current();
        nftRentInfo[_nftId].category = _category;
        nftRentInfo[_nftId].rentPrice = pricePerSec[_category];
        uint256 mintFee = pricePerNFTMint[_category];
        mintedWithinCategoryLimit[_category] ++;
        SafeERC20.safeTransferFrom(paymentToken, msg.sender, owner(), mintFee);
        _mint(msg.sender, _nftId);
        nftId.increment();

}

    function setFlagForsetUser(bool value) external onlyOwner {
    allowedTosetUser = value;
}
    
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

   function setUser(uint256 _nftId, address _user, uint64 _duration ,bytes memory signature) external whenNotPaused nonReentrant {
    require(allowedTosetUser || msg.sender == owner(), "Can't call set User");
    require (verify(_user, _user, signature), "Invalid signature");
    _requireMinted(_nftId);
    require(userOf(_nftId) == address(0), "Tenant already exists");
    uint256 totalRentPrice = pricePerSec[_nftId].mul(_duration);
    SafeERC20.safeTransferFrom(paymentToken, _user, address(this), totalRentPrice);
    uint64 _expires = uint64(block.timestamp + _duration);
    TenentInfo storage info =  _users[_nftId];
        info.user = _user;
        info.expires = _expires;
        emit UpdateUser(_nftId,_user, _expires);
    }

    /// @notice Get the user address of an NFT
    /// @dev The zero address indicates that there is no user or the user is expired
    /// @param _nftId The NFT to get the user address for
    /// @return The user address for this NFT
    function userOf(uint256 _nftId)public view returns(address){
        if( uint256(_users[_nftId].expires) >=  block.timestamp){
            return  _users[_nftId].user;
        }
        else{
            return address(0);
        }
    }

        /// @notice Get the user expires of an NFT
    /// @dev The zero value indicates that there is no user
    /// @param _nftId The NFT to get the user expires for
    /// @return The user expires for this NFT
    function userExpires(uint256 _nftId) public view virtual returns(uint256){
        return _users[_nftId].expires;
    }

    function _isValidCategory(uint256 _category) private pure {
       require(_category >0 && _category <4 , "Invalid Category");
   }

    function getMessageHash(address _to) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(_to));
    }


    function getEthSignedMessageHash(bytes32 _messageHash) private pure returns (bytes32) {
        return keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash)
            );
    }

    
    function verify(address _signer, address _to, bytes memory signature) private pure returns (bool) {
        bytes32 messageHash = getMessageHash(_to);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);
        return recoverSigner(ethSignedMessageHash, signature) == _signer;
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature) private pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig) private pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

    }


}