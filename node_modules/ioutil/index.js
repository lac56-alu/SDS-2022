const fs = require('fs');
const cwd = () => fs.realpathSync(process.cwd());

const findUp = (fn, options = {}) => {
    let dir = options.cwd || cwd();
    const { root } = path.parse(dir);
    let found = fn(dir);
    while(!found && root !== dir) {
        dir = path.dirname(dir);
        found = fn(dir);
    }
    return found;
}

module.exports = {
    findUp,
}
