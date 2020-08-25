import { Resolver, Mutation, InputType, Field, Arg, Ctx, ObjectType } from "type-graphql";
import { MyContext } from "src/types";
import { User } from "../entities/User";
import argon2 from 'argon2';

@InputType()
class UseramePasswordInput{
    @Field()
    username:string
    @Field()
    password:string
}

@ObjectType()
class FieldError{
    @Field()
    field:string;
    @Field()
    message:string;
}

@ObjectType()
class UserResponse{
    @Field(()=>[FieldError],{nullable:true})
    errors?:FieldError[];

    @Field(()=>User,{nullable:true})
    user?:User;
}

@Resolver()
export class UserResolver{
    @Mutation(()=>UserResponse)
    async register(
        @Arg('options') options:UseramePasswordInput,
        @Ctx(){em}:MyContext
    )
    :Promise<UserResponse>
    {
        if(options.username.length<2){
            return{
                errors:[{
                    field:'username',
                    message:'username must contain more than 2 letters'
                }]
            }
        }
        if(options.password.length<2){
            return{
                errors:[{
                    field:'pssword',
                    message:'password must contain more than 2 letters'
                }]
            }
        }
        const hashedPassword=await argon2.hash(options.password);
        const user=em.create(User,{username:options.username,password:hashedPassword});
        try {
            await em.persistAndFlush(user);
            
            
        } catch (err) {
            if(err.code==='23505'){
                return{
                    errors:[{
                        field:'username',
                        message:'username already exists',
                    },]
                }
            };
            console.log(err.message);
        }
        return {user};
        
    }
    @Mutation(()=>UserResponse)
    async login(
        @Arg('options') options:UseramePasswordInput,
        @Ctx(){em}:MyContext
    ):Promise<UserResponse>{
        const user= await em.findOne(User,{username:options.username});
        if(!user){
            return{
                errors:[{
                    field:'username',
                    message:'could not find a valid user'
                }]
            }
        }
        const valid=await argon2.verify(user.password,options.password);
        if(!valid){
            return{
                errors:[{
                    field:'password',
                    message:'incorrect Password'
                }]
            }
        }

        return {
            user,
        };
    }
}