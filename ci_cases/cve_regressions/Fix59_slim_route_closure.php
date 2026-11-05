<?php
// Slim-style route closure: framework-dispatched, no direct cg edge.
// If the dead-code gate kills sinks here, every route handler is blind.
$app->get('/cmd/{c}', function ($request, $response, $args) {
    $cmd = $request->getQueryParams()['cmd'];
    system($cmd);   // real sink inside route closure
    return $response;
});
