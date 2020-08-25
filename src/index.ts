import 'reflect-metadata';
import {MikroORM} from "@mikro-orm/core";
import { __prod__ } from "./constants";
// import { Post } from "./entities/Posts";
import microConfig from "./mikro-orm.config"
import express from 'express'
import {ApolloServer} from 'apollo-server-express'
import{buildSchema} from 'type-graphql'
import { HelloResolver } from "./resolvers/hello";
import { PostResolver } from "./resolvers/post";
import { UserResolver } from './resolvers/user';


import redis from 'redis';
import session from 'express-session';

let RedisStore = require('connect-redis')(session)
let redisClient = redis.createClient()

app.use(
  session({
    store: new RedisStore({ client: redisClient }),
    secret: 'keyboard cat',
    resave: false,
  })
)


const main=async()=>{
    const orm=await MikroORM.init(microConfig);
    await orm.getMigrator().up();

    const app=express();
    const apolloServer=new ApolloServer({
        schema:await buildSchema({
            resolvers:[HelloResolver,PostResolver,UserResolver],
            validate:false
        }),
        context:()=>({em:orm.em})
    });

    apolloServer.applyMiddleware({app});
    
    app.listen(4000,()=>{
        console.log('Server started at localhost:4000');
    });
};

main();
