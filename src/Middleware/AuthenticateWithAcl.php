<?php

namespace Uzzal\Acl\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Factory as Auth;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Uzzal\Acl\Services\PermissionCheckService;
use Illuminate\Support\Facades\Route;

class AuthenticateWithAcl
{

    protected $auth;

    public function __construct(Auth $auth)
    {
        $this->auth = $auth;
    }

    public function handle(Request $request, Closure $next)
    {
        $guards = config('acl.guards', ['web']);
        $defaultGuard = config('auth.defaults.guard', 'web');

        foreach ($guards as $guard) {
            if ($this->auth->guard($guard)->check()) {
                $user = $this->auth->guard($guard)->user();
                // Check for permissions
                if (!PermissionCheckService::canAccess(Route::currentRouteAction(), $user)) {
                    return response()->view('errors.403', [], 403);
                }

                return $next($request);
            }
        }

        return response()->view('errors.403', [], 403);
    }

}
