const passport = require('passport')

const localStrategy = require('passport-local').Strategy
const bcrypt =  require ('bcrypt')

function initialize(password, getUserByEmail, getUserByID) {
    // use done when we are done with authentication
    const authenticateUser = async (email, password, done) => {  
        const user = getUserByEmail(email)
        if(user == null){
            return done(null , false, {message : 'No User with that email address'})
        }

        try{
            if( await bcrypt.compare( password, user.password)){
                return done(null, user)
            }else {
                return done(null, false, {message: 'Password incorrect'})
            }

        }catch (e) {
            return done(e)

        }
    }
    passport.use(new localStrategy ({usernameField: 'email'}, authenticateUser ))
    passport.serializeUser((user, done) => done(null , user.id  ))
    passport.deserializeUser((id, done) => {
        return done(null , getUserByID(id)  ) // seserial user by single ID
    })

} 

module.exports = initialize