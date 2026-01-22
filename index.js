"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Finik = void 0;
/* External dependencies */
var authorizer_1 = require("@mancho.devs/authorizer");
var uuid_1 = require("uuid");
var Finik = /** @class */ (function () {
    function Finik() {
    }
    Finik.prototype.getBaseUrl = function () {
        var baseUrl = undefined === "prod"
            ? "https://api.acquiring.averspay.kg"
            : "https://beta.api.acquiring.averspay.kg";
        return baseUrl;
    };
    Finik.prototype.getHostFromUrl = function (url) {
        var host = new URL(url).host;
        return host;
    };
    Finik.prototype.prepareHeaders = function (apiKey) {
        var baseUrl = this.getBaseUrl();
        var host = this.getHostFromUrl(baseUrl);
        var timestamp = Date.now().toString();
        var headers = {
            Host: host,
            "x-api-key": apiKey,
            "x-api-timestamp": timestamp,
        };
        if (!this.headers) {
            this.headers = headers;
        }
        return this.headers;
    };
    Finik.prototype.prepareRequestData = function (input) {
        var apiKey = input.apiKey, body = input.body;
        var paymentId = (0, uuid_1.v4)();
        body["PaymentId"] = paymentId;
        var requestData = {
            httpMethod: "POST",
            path: "/v1/payment",
            headers: this.prepareHeaders(apiKey),
            queryStringParameters: undefined,
            body: body,
        };
        return requestData;
    };
    Finik.prototype.generateSignature = function (requestData, privateKey) {
        return __awaiter(this, void 0, void 0, function () {
            var signature;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, new authorizer_1.Signer(requestData).sign(privateKey)];
                    case 1:
                        signature = _a.sent();
                        return [2 /*return*/, signature];
                }
            });
        });
    };
    Finik.prototype.makePayment = function (input) {
        return __awaiter(this, void 0, void 0, function () {
            var apiKey, privateKey, body, requestData, signature, url, res, paymentUrl, _a, _b, _c;
            return __generator(this, function (_d) {
                switch (_d.label) {
                    case 0:
                        apiKey = input.apiKey, privateKey = input.privateKey, body = input.body;
                        requestData = this.prepareRequestData(input);
                        return [4 /*yield*/, this.generateSignature(requestData, privateKey)];
                    case 1:
                        signature = _d.sent();
                        url = "".concat(this.getBaseUrl()).concat(requestData.path);
                        return [4 /*yield*/, fetch(url, {
                                method: requestData.httpMethod,
                                headers: __assign(__assign({}, this.prepareHeaders(apiKey)), { "content-type": "application/json", signature: signature }),
                                body: JSON.stringify(body),
                                redirect: "manual",
                            })];
                    case 2:
                        res = _d.sent();
                        if (!(res.status === 302)) return [3 /*break*/, 3];
                        paymentUrl = res.headers.get("location");
                        console.log("paymentURL", paymentUrl);
                        return [2 /*return*/, paymentUrl];
                    case 3:
                        _b = (_a = console).error;
                        _c = [res.status];
                        return [4 /*yield*/, res.text()];
                    case 4:
                        _b.apply(_a, _c.concat([_d.sent()]));
                        return [2 /*return*/, "error caused"];
                }
            });
        });
    };
    return Finik;
}());
exports.Finik = Finik;
