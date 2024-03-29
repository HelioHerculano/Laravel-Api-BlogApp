<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    //Register user
    public function register(Request $request)
    {

        $rule = [
            'name' => 'required|string',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|min:6|confirmed'
        ];
        //validate fields
        $validate = Validator::make($request->all(),$rule);

        if($validate->fails()){
            return response($validate->errors(),200);
        }
        //create user
        $attrs = $request->only('name','email','password');
        $user = User::create([
            'name' => $attrs['name'],
            'email' => $attrs['email'],
            'password' => bcrypt($attrs['password'])
        ]);

        //return user & token in response
        return response([
            'user' => $user,
            'token' => $user->createToken('secret')->plainTextToken
        ], 200);
    }

    // login user
    public function login(Request $request)
    {
        //validate fields
        $rules = [
            'email' => 'required|email',
            'password' => 'required|min:6'
        ];

        $validate = Validator::make($request->all(),$rules);

        if($validate->fails()){
            return response(["errors"=>$validate->errors()],422);
        }

        $attrs = $request->all();
        // attempt login
        if(!Auth::attempt($attrs))
        {
            return response([
                'message' => 'Invalid credentials.'
            ], 403);
        }

        //return user & token in response
        return response([
            'user' => auth()->user(),
            'token' => auth()->user()->createToken('secret')->plainTextToken
        ], 200);
    }

    // logout user
    public function logout()
    {
        auth()->user()->tokens()->delete();
        return response([
            'message' => 'Logout success.'
        ], 200);
    }

    // get user details
    public function user()
    {
        return response([
            'user' => auth()->user()
        ], 200);
    }

    // update user
    public function update(Request $request)
    {
        $rules = [
            'name' => 'required|string'
        ];

        $validate = Validator::make($request->all(),$rules);

        if($validate->fails()){
            return response($validate->errors(),422);
        }

        $image = $this->saveImage($request->image, 'profiles');

        $attrs = $request->all();

        auth()->user()->update([
            'name' => $attrs['name'],
            'image' => $image
        ]);

        return response([
            'message' => 'User updated.',
            'user' => auth()->user()
        ], 200);
    }
}
