<?php

namespace App\Http\Controllers;

use App\Models\Post;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class PostController extends Controller
{
    public function index()
    {
        return response([
            'posts' => Post::orderBy('created_at', 'desc')->with('user:id,name,image')->withCount('comments', 'likes')
            ->with('likes', function($like){
                return $like->where('user_id', auth()->user()->id)
                    ->select('id', 'user_id', 'post_id')->get();
            })
            ->get()
        ], 200);
    }

    // get single post
    public function show($id)
    {
        return response([
            'post' => Post::where('id', $id)->withCount('comments', 'likes')->get()
        ], 200);
    }

    // create a post
    public function store(Request $request)
    {
        //validate fields
        $rules = [
            'body' => 'required|string'
        ];

        $validate = Validator::make($request->all(), $rules);

        if($validate->fails()){
            return response($validate->errors(),422);
        }

        $image = $this->saveImage($request->image, 'posts');
        $attrs = $request->all();

        $post = Post::create([
            'body' => $attrs['body'],
            'user_id' => auth()->user()->id,
            'image' => $image
        ]);

        // for now skip for post image

        return response([
            'message' => 'Post created.',
            'post' => $post,
        ], 200);
    }

    // update a post
    public function update(Request $request, $id)
    {
        $post = Post::find($id);

        if(!$post)
        {
            return response([
                'message' => 'Post not found.'
            ], 403);
        }

        if($post->user_id != auth()->user()->id)
        {
            return response([
                'message' => 'Permission denied.'
            ], 403);
        }

        //validate fields
        $rules = [
            'body' => 'required|string'
        ];

        $validate = Validator::make($request->all(),$rules);

        if($validate->fails()){
            return response($validate->errors(),422);
        }

        $attrs = $request->all();

        $post->update([
            'body' =>  $attrs['body']
        ]);

        // for now skip for post image

        return response([
            'message' => 'Post updated.',
            'post' => $post
        ], 200);
    }

    //delete post
    public function destroy($id)
    {
        $post = Post::find($id);
        if(!$post)

        {
            return response([
                'message' => 'Post not found.'
            ], 403);
        }

        if($post->user_id != auth()->user()->id)
        {
            return response([
                'message' => 'Permission denied.'
            ], 403);
        }

        $post->comments()->delete();
        $post->likes()->delete();
        $post->delete();

        return response([
            'message' => 'Post deleted.'
        ], 200);
    }
}
