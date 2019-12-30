<?php

namespace Laravel\Passport\Bridge;

use Laravel\Passport\Passport;

trait ValidateUsersScopes
{
    /**
     *
     *
     * @param User $user
     * @param $scopes
     */
    protected function validateUserScopes($user, $scopes)
    {
        $availableScopes = $user->user()->availableScopes();

        if ($availableScopes === true) {
            return $scopes;
        } else {
            $scopes = collect($scopes);
            if ($scopes->count() == 1 && $scopes->first()->getIdentifier() == '*') {
                return collect(Passport::scopes())->whereIn('id', $availableScopes)->pluck('id')
                    ->mapInto(\Laravel\Passport\Bridge\Scope::class)->toArray();
            }
            $blocked = $scopes->whereNotIn('getIdentifier', $availableScopes);
            return $blocked->isEmpty() ? $scopes->whereIn('getIdentifier', $availableScopes)->toArray() : null;
        }
    }
}
