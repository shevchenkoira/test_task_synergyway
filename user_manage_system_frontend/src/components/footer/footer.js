import React from "react";
import {BASE_URL} from "../../utils/utils";
import "./footer.css"

export default function Footer() {
  return (
      <div className="footer-basic">
        <footer>
          <ul className="list-inline">
            <li className="list-inline-item"><a href={"/users/"}>Users</a></li>
            <li className="list-inline-item"><a href={"/groups/"}>Groups</a></li>
          </ul>
          <p className="copyright">Test task by Ira Shevchenko © 2022</p>
        </footer>
      </div>
  );
}