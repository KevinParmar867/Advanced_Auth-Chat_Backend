const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const key = "hvsdfavsdvhvjhvjhvhvjhve"; // must be 24bytes string // aes256 32byte string
const iv = crypto.randomBytes(16);
const algorithm = "aes192";
const encoding = "hex";

// Generate Token
const generateToken = (id) => {
    return jwt.sign({id}, process.env.JWT_SECRET, { expiresIn: "1d" });
};

// Hash Token
const hashToken = (token) => {
    return crypto.createHash("sha256").update(token.toString()).digest("hex");
};

// encrypt Token for mail
const encrypt = (text) => {
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    cipher.update(text);
    return cipher.final(encoding);
};

// decrypt Token for mail
const decrypt = (text) => {
    
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(text, encoding, 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
};

module.exports = {
    generateToken,
    hashToken,
    encrypt,
    decrypt,
};
