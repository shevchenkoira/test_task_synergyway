import React from "react";
import './App.css';
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Footer from "./components/footer/footer";
import Header from "./components/header/header";
import UsersList from "./components/users_list/UsersList";
import GroupsList from "./components/group_list/GroupsList";
import AddUser from "./components/add_user/AddUser";
import EditUser from "./components/edit_user/EditUser";
import EditGroup from "./components/edit_group/EditGroup";
import AddGroup from "./components/add_group/AddGroup";

class App extends React.Component{
  render() {
    return (
        <Router>
            <Header> </Header>
            <Routes>
                        <Route path="/users" element={<UsersList/>}>
                        </Route>
                        <Route path="/groups" element={<GroupsList/>}>
                        </Route>
                        <Route path="/add_user" element={<AddUser/>}>
                        </Route>
                        <Route path="/add_group" element={<AddGroup/>}>
                        </Route>
                        <Route path="/edit_user/:id" element={<EditUser/>}>
                        </Route>
                        <Route path="/edit_group/:id" element={<EditGroup/>}>
                        {/*</Route>*/}
                        {/*<Route path="/user/:userId" element={<ParticularUser/>}>*/}
                        {/*</Route>*/}
                        {/*<Route path="/group/:groupId" element={<ParticularGroup />} />*/}
                        {/*<Route path="/about" element={<AboutPage/>}>*/}
                        </Route>
                    </Routes>
            <Footer> </Footer>
        </Router>
    )
  }

}

export default App;
