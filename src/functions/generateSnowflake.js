module.exports = () => {
    return `${Date.now()}${randomNumber(1000, 9999)}`
}

function randomNumber(min, max) {
    return Math.floor(Math.random() * (max - min + 1) + min);
}