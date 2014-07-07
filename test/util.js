exports.bufferEquals = function (lhs, rhs) {
    var i;

    if (lhs.length !== rhs.length) { return false; }

    for (i = 0; i < lhs.length; i++) {
        if (lhs[i] !== rhs[i]) { return false; }
    }

    return true;
};
