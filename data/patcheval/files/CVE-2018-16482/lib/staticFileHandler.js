var fs = require('fs');
var path = require('path');
var assert = require('assert');
var httpHelpers = require('./httpHelpers');
var statusHandlers = require('./statusHandlers');
var responseHandlers = require('./responseHandlers');

module.exports = function staticFileListener(options, nextHandler){
    assert(options.root,'A root must be defined');
    assert(options.getMockPaths,'A get mock path object must be defined');
    assert(options.putMockPaths,'A put mock path object must be defined');
    assert(options.postMockPaths,'A post mock path object must be defined');
    assert(options.deleteMockPaths,'A delete mock path object must be defined');

    return function(req,res){
        var root = options.root;
        var mockPaths = getMockPathForMethod(options,req.method);

        var filePath = httpHelpers.getRequestPathFromUrl(req.url);
        var mockedFilePath = findMockFilePath(filePath,mockPaths);
        if(mockedFilePath)
            filePath = mockedFilePath;

        var file = path.normalize(path.join(root,filePath));
        fs.stat(file,function(error, stats){
            if(error)
                return statusHandlers[500](res, nextHandler, { error: error });

            if(req.method === 'HEAD')
                return responseHandlers.handleHead(req,res);
            
            httpHelpers.setContentType(res,file);
            if (req.headers && req.headers['range'])
                return responseHandlers.handleRange(req, file, stats);

            if(!req.method)
                return statusHandlers[500](res, nextHandler, { error: 'Method not handled' });

            if (req.method === 'GET')
                return responseHandlers.handleGet(res,file, stats, nextHandler);
            if (req.method === 'POST')
                return responseHandlers.handlePost(res,file, stats, nextHandler);
            if (req.method === 'PUT')
                return responseHandlers.handlePut(res,file, stats, nextHandler);
            if (req.method === 'DELETE')
                return responseHandlers.handleDelete(res, file, stats, nextHandler);
        });
    };
};

var getMockPathForMethod = function(mockPaths,method){
    if (method === 'GET')
        return mockPaths.getMockPaths;
    if (method === 'POST')
        return mockPaths.postMockPaths;
    if (method === 'PUT')
        return mockPaths.putMockPaths;
    if (method === 'DELETE')
        return mockPaths.deleteMockPaths;
};

var findMockFilePath = function(filePath,mockPaths){
    var mocks = this;

    if(mockPaths[filePath])
        return mockPaths[filePath];

    for(var mockPath in mockPaths){
        if(filePath.indexOf(mockPath) >= 0)
            return filePath.replace(new RegExp(mockPath, "g"), mockPaths[mockPath]);
    }

    return undefined;
};