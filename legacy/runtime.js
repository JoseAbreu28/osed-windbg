// Legacy runtime for WinDbg JsProvider builds without BigInt (classic WinDbg 10.0.19041).
// Bigint values are represented as integral Numbers. Any value outside the
// safe-integer range throws instead of silently losing precision.
var __bi = (function () {
  var TWO32 = 4294967296;

  function check(value, what) {
    if (!Number.isSafeInteger(value)) {
      throw new RangeError("osed legacy build: " + what + " is outside the 53-bit safe range (" + value + ")");
    }
    return value;
  }

  function parse(text) {
    var s = String(text).trim();
    if (s === "") return 0;
    if (/^[+-]?\d+$/.test(s)) return check(Number(s), "BigInt(\"" + s + "\")");
    var m = /^0([xob])([0-9a-f]+)$/i.exec(s);
    if (m) {
      var radix = { x: 16, o: 8, b: 2 }[m[1].toLowerCase()];
      var digits = m[2];
      var valid = radix === 16 ? /^[0-9a-f]+$/i : radix === 8 ? /^[0-7]+$/ : /^[01]+$/;
      if (valid.test(digits)) return check(parseInt(digits, radix), "BigInt(\"" + s + "\")");
    }
    throw new SyntaxError("Cannot convert " + s + " to a BigInt");
  }

  function toBig(value) {
    switch (typeof value) {
      case "number":
        if (!Number.isInteger(value)) throw new RangeError("The number " + value + " cannot be converted to a BigInt because it is not an integer");
        return check(value, "BigInt(" + value + ")");
      case "string":
        return parse(value);
      case "boolean":
        return value ? 1 : 0;
      case "bigint":
        return check(Number(value), "BigInt(" + value + ")");
      case "object":
      case "function":
        if (value !== null) {
          var primitive = value.valueOf();
          if (primitive !== value && (typeof primitive !== "object" || primitive === null)) return toBig(primitive);
          return parse(String(value));
        }
    }
    throw new TypeError("Cannot convert " + value + " to a BigInt");
  }

  function split(v) {
    var hi = Math.floor(v / TWO32);
    return { hi: hi, lo: v - hi * TWO32 };
  }

  function join(hi, lo) {
    return check(hi * TWO32 + (lo >>> 0), "bitwise result");
  }

  toBig.and = function (a, b) {
    var x = split(a), y = split(b);
    return join(x.hi & y.hi, x.lo & y.lo);
  };
  toBig.or = function (a, b) {
    var x = split(a), y = split(b);
    return join(x.hi | y.hi, x.lo | y.lo);
  };
  toBig.xor = function (a, b) {
    var x = split(a), y = split(b);
    return join(x.hi ^ y.hi, x.lo ^ y.lo);
  };
  toBig.shl = function (a, n) {
    if (n < 0) return toBig.shr(a, -n);
    return check(a * Math.pow(2, n), "left shift");
  };
  toBig.shr = function (a, n) {
    if (n < 0) return toBig.shl(a, -n);
    return Math.floor(a / Math.pow(2, n));
  };
  toBig.mul = function (a, b) {
    return check(a * b, "multiplication");
  };
  toBig.div = function (a, b) {
    if (b === 0) throw new RangeError("Division by zero");
    var q = Math.trunc(a / b);
    var r = a - q * b;
    var step = (a < 0) === (b < 0) ? 1 : -1;
    if (r !== 0 && (r < 0) !== (a < 0)) q -= step;
    else if (Math.abs(r) >= Math.abs(b)) q += step;
    return q === 0 ? 0 : q;
  };
  toBig.asUintN = function (bits, v) {
    if (bits > 53) {
      if (v < 0) throw new RangeError("osed legacy build: asUintN(" + bits + ") of a negative value is outside the 53-bit safe range");
      return v;
    }
    var mod = Math.pow(2, bits);
    var r = v % mod;
    return r < 0 ? r + mod : r === 0 ? 0 : r;
  };
  toBig.asIntN = function (bits, v) {
    if (bits > 53) return v;
    var mod = Math.pow(2, bits);
    var r = toBig.asUintN(bits, v);
    return r >= mod / 2 ? r - mod : r;
  };
  return toBig;
})();

// Old Chakra sorts unstably; ES2019 engines keep ties in input order, which rankings rely on.
(function () {
  var nativeSort = Array.prototype.sort;
  Object.defineProperty(Array.prototype, "sort", {
    configurable: true,
    writable: true,
    value: function sort(compare) {
      if (typeof compare !== "function") return nativeSort.call(this, compare);
      var decorated = [], undefinedCount = 0, length = this.length >>> 0, i;
      for (i = 0; i < length; i++) {
        if (!(i in this)) continue;
        if (this[i] === undefined) undefinedCount++;
        else decorated.push({ value: this[i], index: i });
      }
      nativeSort.call(decorated, function (a, b) {
        return compare(a.value, b.value) || a.index - b.index;
      });
      var at = 0;
      for (i = 0; i < decorated.length; i++) this[at++] = decorated[i].value;
      for (i = 0; i < undefinedCount; i++) this[at++] = undefined;
      while (at < length) delete this[at++];
      return this;
    },
  });
})();

if (!Array.prototype.flat) {
  Object.defineProperty(Array.prototype, "flat", {
    configurable: true,
    writable: true,
    value: function flat(depth) {
      var d = depth === undefined ? 1 : Number(depth);
      var out = [];
      (function walk(arr, level) {
        for (var i = 0; i < arr.length; i++) {
          if (!(i in arr)) continue;
          if (Array.isArray(arr[i]) && level > 0) walk(arr[i], level - 1);
          else out.push(arr[i]);
        }
      })(this, d);
      return out;
    },
  });
}
if (!Array.prototype.flatMap) {
  Object.defineProperty(Array.prototype, "flatMap", {
    configurable: true,
    writable: true,
    value: function flatMap(fn, thisArg) {
      return Array.prototype.map.call(this, fn, thisArg).flat(1);
    },
  });
}
if (!Object.fromEntries) {
  Object.fromEntries = function fromEntries(entries) {
    var out = {};
    for (var pair of entries) out[pair[0]] = pair[1];
    return out;
  };
}
if (!String.prototype.trimEnd) {
  String.prototype.trimEnd = String.prototype.trimRight || function () { return String(this).replace(/\s+$/, ""); };
}
if (!String.prototype.trimStart) {
  String.prototype.trimStart = String.prototype.trimLeft || function () { return String(this).replace(/^\s+/, ""); };
}
